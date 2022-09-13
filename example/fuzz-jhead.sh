nohup timeout 86400 mirage-fuzz -E -m none -i ./jhead-init-seed -o out-test -S phan -D ./jhead-pin ./jhead-phan @@ > /dev/null & 
sleep 1
nohup timeout 86400 mirage-fuzz -m none -i ./jhead-init-seed -o out-test -S asan ./jhead-asan @@ > /dev/null &
sleep 10
nohup timeout 86400 mirage-fuzz -m none -i ./jhead-init-seed -o out-test -S src -D ./jhead-pin ./jhead-src @@ > /dev/null &
