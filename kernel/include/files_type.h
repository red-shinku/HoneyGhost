/**
 * @file files_type.h
 * @brief 此文件定义文件事件收集模块的数据结构，
 * 便于统一 内核态 / 用户态结构定义
 * 用户态直接引用该头文件以使用相关结构
 * @author red_shinku
 * @date 2026.08.12
 */

#ifndef _BPF_FILE_TYPE_H_
#define _BPF_FILE_TYPE_H_

#include "../include/event_head.h"

/**
 * @brief 每个文件事件都会生成该结构的对象
 */
struct file_access_data {
    struct event_head head;

    char comm[16];        ///< 打开文件的程序
    char filename[256];   ///< 打开文件路径，文件名
    __u32 flags;          ///< 文件打开方式
    __u8 is_innamespace;  ///< 是否处于非初始 mount 命名空间（见 files.bpf.c）
};

#endif  //_BPF_FILE_TYPE_H_