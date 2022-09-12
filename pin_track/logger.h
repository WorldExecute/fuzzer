
#ifndef LOGGER_H
#define LOGGER_H

// TODO: support multiple thread

#include "cond_stmt.h"
#include "libdft_api.h"
#include <set>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/shm.h>

#define SHM_TAINT_MAP_ENV_VAR "__TAINT_MAP_SHM_ID"
#define SHM_PHANTOM_TAINT_MAP_ENV_VAR         "__PHANTOM_TAINT_MAP_SHM_ID"
#define TRACK_COND_OUTPUT_VAR "ANGORA_TRACK_OUTPUT"

#define BUF_LEN (2 << 16)
class LogBuf{
        private:
        char *buffer;
        size_t cap;
        size_t len;

        public:
        void push_bytes(char *bytes, std::size_t size) {
            if (size > 0 && bytes) {
                size_t next = len + size;
                if (next > cap) {
                    cap *= 2;
                    buffer = (char *) realloc(buffer, cap);
                }
                memcpy(buffer + len, bytes, size);
                len = len + size;
            }
        };

        void write_file(FILE *out_f) {
            if (!out_f || len == 0)
                return;
            int nr = fwrite(buffer, len, 1, out_f);
            if (nr < 1) {
                fprintf(stderr, "fail to write file %d %lu\n", nr, len);
                exit(1);
            }
        };

        LogBuf() {
            cap = BUF_LEN;
            buffer = (char *) malloc(cap);
            len = 0;
        };
        ~LogBuf() { free(buffer); }
};

class BranchLogBuf{
        private:
        TagSeg *taint_map;
        public:

        bool isShm;


        BranchLogBuf() {
            taint_map = nullptr;
        }

        void bindStorage(bool isPhantomMode) {
            if (taint_map) delete [] taint_map;
            char *__taint_map_str = isPhantomMode? 
                    getenv(SHM_PHANTOM_TAINT_MAP_ENV_VAR) 
                    : getenv(SHM_TAINT_MAP_ENV_VAR);
            isShm = !!(__taint_map_str);
            if (isShm) {
                u32 shm_id = atoi(__taint_map_str);
                taint_map = (TagSeg *)shmat(shm_id, NULL, 0);
                /* Whooooops. */

                if (taint_map == (void *) -1) _exit(1);
            } else {
                taint_map = new TagSeg[1 << 16];
            }

            // if (isPhantomMode) {
            //     taint_map = new TagSeg[1 << 16];
            //     isShm = false;
            // } else {
            //     if (taint_map) delete [] taint_map;
            //     char *__taint_map_str = getenv(SHM_TAINT_MAP_ENV_VAR);
            //     isShm = !!(__taint_map_str);
            //     if (isShm) {
            //         u32 shm_id = atoi(__taint_map_str);
            //         taint_map = (TagSeg *)shmat(shm_id, NULL, 0);
            //         /* Whooooops. */

            //         if (taint_map == (void *) -1) _exit(1);
            //     } else {
            //         taint_map = new TagSeg[1 << 16];
            //     }
            // }
        }


        void put(s32 thenEdge, s32 elseEdge, TagSeg seg) {
            if (thenEdge >= 0 && *((u64*)(taint_map + thenEdge)) == 0)
                taint_map[thenEdge] = seg;
            if (elseEdge >= 0 && *((u64*)(taint_map + elseEdge)) == 0)
                taint_map[elseEdge] = seg;
        };

        void write_file(FILE *out_f) {
            if (isShm || !out_f)
                return;
            int nr = fwrite(taint_map, sizeof(TagSeg), 1 << 16, out_f);
            if (nr < 1) {
                fprintf(stderr, "fail to write file %d\n", nr);
                exit(1);
            }
        };

};

class Logger{
        private:
        bool phantomMode;
        u32 num_branch;
        u32 num_cond;
        u32 num_tag;
        u32 num_mb;
        BranchLogBuf br_buf;
        LogBuf branch_buf;
        LogBuf cond_buf;
        LogBuf tag_buf;
        LogBuf mb_buf;
        std::map<u64, u32> order_map;
        std::set<lb_type> lb_set;

        const char *out_file;

        public:
        Logger(){};
        ~Logger(){};

        void set_mode(bool mode) {
            phantomMode = mode;
            br_buf.bindStorage(mode);
        }
        
        void set_outfile(const char *outfile) {
            out_file = outfile;
        }

        void save_buffers() {
            FILE *out_f = NULL;
            char *track_file = getenv(TRACK_COND_OUTPUT_VAR);
            if (track_file) {
                out_f = fopen(track_file, "w");
            } else {
                out_f = fopen("track.out", "w");
            }

            fwrite(&num_branch, 4, 1, out_f);
            fwrite(&num_tag, 4, 1, out_f);
            fwrite(&num_cond, 4, 1, out_f);
            fwrite(&num_mb, 4, 1, out_f);

            branch_buf.write_file(out_f);
            tag_buf.write_file(out_f);
            cond_buf.write_file(out_f);
            mb_buf.write_file(out_f);

            if (out_f) {
                fclose(out_f);
                out_f = NULL;
            }
        }

        void save_br_buf_only() {
            if (br_buf.isShm) {
                return;
            }
            FILE *out_f = NULL;
            if (out_file) {
                out_f = fopen(out_file, "w");
            } else {
                out_f = fopen("track.out", "w");
            }
            br_buf.write_file(out_f);
            if (out_f) {
                fclose(out_f);
                out_f = NULL;
            }
        }

        u32 get_order(u32 cid, u32 ctx) {
            u64 key = cid;
            key = (key << 32) | ctx;
            u32 ctr = 1;
            if (order_map.count(key) > 0) {
                ctr = order_map[key] + 1;
                order_map[key] = ctr;
            } else {
                order_map.insert(std::pair<u64, u32>(key, 1));
            }
            return ctr;
        }

        std::vector<TagSeg> get_merge(lb_type lb){
            std::vector <tag_seg> t = tag_get(lb);
            std::vector <TagSeg> merge;
            u32 n = t.size();
            TagSeg seg = {0, 0};
            for (u32 i = 0; i != n; i++) {
                tag_seg tmp_seg = t[i];
                if (seg.begin == seg.end) {
                    seg.begin = tmp_seg.begin;
                    seg.end = tmp_seg.end;
                } else if (seg.begin <= tmp_seg.begin && seg.end < tmp_seg.end) {
                    seg.end = tmp_seg.end;
                } else if (seg.begin <= tmp_seg.begin && tmp_seg.end <= seg.end) {

                } else {
                    merge.push_back(seg);
                    seg = {0, 0};
                }

            }
            merge.push_back(seg);

            return merge;
        }

        void save_branch_simple(s32 thenEdge, s32 elseEdge, lb_type lb) {
            num_branch++;
            assert(!BDD_HAS_LEN_LB(lb));
            u32 min_loc, max_loc;
            if (lb > 0 && lb_set.count(lb) == 0) {
                std::vector <TagSeg> t = get_merge(lb);
                u32 n = t.size();
                min_loc = t[0].begin;
                max_loc = t[n - 1].end;

                TagSeg seg = {min_loc, max_loc};
                br_buf.put(thenEdge, elseEdge, seg);
            }
        }

        void save_branch(s32 thenEdge, s32 elseEdge, u32 cond, u32 op,
        u64 arg1, u64 arg2, lb_type lb) {
            num_branch++;
            assert(!BDD_HAS_LEN_LB(lb));
            u32 min_loc, max_loc;
            if (lb > 0 && lb_set.count(lb) == 0) {
                std::vector <TagSeg> t = get_merge(lb);
                u32 n = t.size();
                min_loc = t[0].begin;
                max_loc = t[n - 1].end;

                TagSeg seg = {min_loc, max_loc};

                br_buf.put(thenEdge, elseEdge, seg);
            }
        }


        void save_tag(lb_type lb) {
            assert(!BDD_HAS_LEN_LB(lb));
            if (lb > 0 && lb_set.count(lb) == 0) {
                std::vector <TagSeg> t = get_merge(lb);
                u32 n = t.size();
                tag_buf.push_bytes((char *) &lb, 4);
                tag_buf.push_bytes((char *) &n, 4);
                tag_buf.push_bytes((char *) &t[0], sizeof(TagSeg) * n);
                num_tag++;
                lb_set.insert(lb);
            }
        };

        void save_mb(u32 i, u32 arg1_len, u32 arg2_len, char *arg1, char *arg2) {
            if (i >= 0) {
                mb_buf.push_bytes((char *) &i, 4);
                mb_buf.push_bytes((char *) &arg1_len, 4);
                mb_buf.push_bytes((char *) &arg2_len, 4);
                mb_buf.push_bytes(arg1, arg1_len);
                mb_buf.push_bytes(arg2, arg2_len);
                num_mb++;
            }
        };

        u32 save_cond(CondStmt &cond) {
            u32 i = num_cond;
            num_cond++;
            save_tag(cond.lb1);
            save_tag(cond.lb2);
            cond_buf.push_bytes((char *) &cond, sizeof(CondStmt));
            return i;
        }

};

#endif