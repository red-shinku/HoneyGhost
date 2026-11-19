/**
 * @file uapi_const.h
 * @brief 集中定义 vmlinux.h 未提供的 UAPI 宏常量
 * @details
 *
 * vmlinux.h 只提供类型定义，不提供宏常量。BPF CO-RE 程序中不能包含宿主机的
 * 系统头文件（如 linux/fcntl.h、linux/sched.h），它们会与 vmlinux.h 的 typedef
 * 冲突，因此此处集中定义各探针程序需要的常量，数值与内核 include/uapi 一致。
 *
 * @author red_shinku
 * @date 2026.08.12
 */

#ifndef __UAPI_CONST_H
#define __UAPI_CONST_H

// 目录基准 fd（include/uapi/linux/fcntl.h）
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

// 文件打开标志（include/uapi/asm-generic/fcntl.h）
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_CREAT
#define O_CREAT 00000100
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif

// 内存保护位（include/uapi/asm-generic/mman-common.h）
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

// 内存映射标志（include/uapi/asm-generic/mman-common.h）
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

// 套接字地址族（include/uapi/linux/socket.h）
#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

// bpf 命令（include/uapi/linux/bpf.h）
#ifndef BPF_MAP_CREATE
#define BPF_MAP_CREATE 0
#endif
#ifndef BPF_PROG_LOAD
#define BPF_PROG_LOAD 5
#endif
#ifndef BPF_PROG_ATTACH
#define BPF_PROG_ATTACH 8
#endif
#ifndef BPF_PROG_DETACH
#define BPF_PROG_DETACH 9
#endif

// 命名空间克隆标志（include/uapi/linux/sched.h）
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

#endif  // __UAPI_CONST_H
