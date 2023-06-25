//
// Created by camsyn on 2022/5/19.
//

#ifndef MIRAGE_FUZZER_UTIL_H
#define MIRAGE_FUZZER_UTIL_H

#define GET_OR_INSERT_READONLY_FUNCTION(callee_obj, ret_ty, func_name, ...)    \
  {                                                                            \
    FunctionType *callee_obj##Ty =                                             \
        FunctionType::get(ret_ty, __VA_ARGS__, false);                         \
    AttributeList AL;                                                          \
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,         \
                         Attribute::NoUnwind);                                 \
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,         \
                         Attribute::ReadOnly);                                 \
    callee_obj = M.getOrInsertFunction(func_name, callee_obj##Ty, AL);         \
  }

#define GET_OR_INSERT_FUNCTION(callee_obj, ret_ty, func_name, ...)             \
  {                                                                            \
    FunctionType *callee_obj##Ty =                                             \
        FunctionType::get(ret_ty, __VA_ARGS__, false);                         \
    AttributeList AL;                                                          \
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,         \
                         Attribute::NoUnwind);                                 \
    callee_obj = M.getOrInsertFunction(func_name, callee_obj##Ty, AL);         \
  }


#endif //MIRAGE_FUZZER_UTIL_H
