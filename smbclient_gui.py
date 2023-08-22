#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Mini shell using some of the SMB functionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMB DCE/RPC
#

from __future__ import division
from __future__ import print_function
import logging
from impacket.examples import logger
from impacket.examples.utils import parse_target
from smbclient_impacket import MiniImpacketShell
from impacket import version
from impacket.smbconnection import SMBConnection
import base64
import tkinter as tk
from tkinter import ttk
import argparse
import sys

def main():
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the mini shell')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('GUI')
    group.add_argument('-gui', action='store_true', help='Use GUI to interact with SMB server')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        global shell
        shell = MiniImpacketShell(smbClient)

        if options.file is not None:
            for line in options.file.splitlines():
                if line[0] != '#':
                    print("# %s" % line, end=' ')
                    shell.onecmd(line)
                else:
                    print(line, end=' ')
        else:
            if(options.gui):
                dir_list, share_directory = initialize_shared_directory()
                create_gui(dir_list)
            else:
                shell.cmdloop()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

def get_shares():
    shell.onecmd('shares')
    return shell.shares_out

def get_ls(command):
    for line in command.splitlines():
        shell.onecmd(line)
    return shell.ls_out

def get_file(command):
    for line in command.splitlines():
        shell.onecmd(line)

def expand_row(event):
    # 获取选中的行
    selected_item = treeview.focus()

    # 判断是否已经展开
    if treeview.item(selected_item, option='tags') == ('expanded',):
        # 收起行
        treeview.item(selected_item, tags=())
    else:
        # 展开行
        treeview.item(selected_item, tags=('expanded',))

def menu_exec_fuc(event):
    # 在鼠标位置显示右键菜单1
    show_menu.post(event.x_root, event.y_root)

def menu_download_fuc(event):
    # 在鼠标位置显示右键菜单2
    show_menu.post(event.x_root, event.y_root)

def close_menu(event):
    # 关闭右键菜单
    show_menu.unpost()


def execute_selected_command(exec_b64,folder_path):
    # 获取选中的行
    selected_item = treeview.focus()
    if(treeview.item(treeview.focus())['values'][1].count('-rw-rw-rw-')>=1):
        treeview.insert(selected_item, "end", text='This File',values=('-', '-', '-', '-'))
        return
    exec_text = base64.b64decode(exec_b64).decode('utf-8')
    exec_text += 'cd '+ folder_path + '\nls\n'
    # 执行选中的命令
    dir_list = get_ls(exec_text)
    # 删除子项
    children = treeview.get_children(selected_item)
    for child in children:
        treeview.delete(child)
    # 添加子项
    for line in dir_list:
        file_name = line[3]
        file_size = line[1]
        file_authority = line[0]
        Creation_time = line[2]
        command = base64.b64encode(exec_text.encode('utf-8')).decode('utf-8')
        treeview.insert(selected_item , "end", text=file_name, values=(file_size, file_authority, Creation_time, command))

def execute_download_command(exec_b64,filename):
    exec_text = base64.b64decode(exec_b64).decode('utf-8')
    exec_text = exec_text + 'get ' + filename + '\n'
    # 执行下载命令
    get_file(exec_text)

def add_column(treeview):
    # 添加列
    treeview["columns"] = ("file_size", "file_authority", "Creation_time", "Modification_time", "command")
    # 设置列的标题
    treeview.heading("#0", text="File_Name")
    treeview.heading("file_size", text="file_size")
    treeview.heading("file_authority", text="file_authority")
    treeview.heading("Creation_time", text="Creation_time")
    treeview.heading("Modification_time", text="Modification_time")

def add_data(treeview, dir_list,share_directory):
    # 添加数据
    for line in dir_list:
        file_name = line[3]
        file_size = line[1]
        file_authority = line[0]
        Creation_time = line[2]
        command = 'use ' + share_directory + '\n'
        command = base64.b64encode(command.encode('utf-8'))
        command = command.decode('utf-8')
        treeview.insert("", "end", text=file_name, values=(file_size, file_authority, Creation_time, command))


def initialize_shared_directory():
    get_shares()
    global share_directory
    share_directory = input("Please enter a shared directory:")
    while True:
        # 初始化共享目录
        # dir_list : 读写权限 文件大小 日期 文件名
        dir_list = get_ls("use {share_directory}\nls".format(share_directory=share_directory))

        if len(dir_list) == 0:
            print("Failed to get directory list. Please try again.")
            share_directory = input("Please enter a shared directory:")
        else:
            break
    return dir_list,share_directory


def create_gui(dir_list):
    # 创建窗口
    window = tk.Tk()
    # 设置窗口标题
    window.title("File Selection")
    # 设置窗口大小
    window.geometry("1620x540")
    # 创建Treeview
    global treeview
    treeview = ttk.Treeview(window)
    treeview.pack(fill="both", expand=True)
    # 添加列
    add_column(treeview)
    # 添加数据
    add_data(treeview, dir_list, share_directory)
    # 绑定展开事件
    treeview.bind("<Double-1>", expand_row)
    # 创建右键菜单1
    global show_menu
    show_menu = tk.Menu(window, tearoff=False)
    show_menu.add_command(label="View dir",command=lambda: execute_selected_command(treeview.item(treeview.focus())['values'][-1],treeview.item(treeview.focus())['text']))
    # 绑定右键点击事件1
    treeview.bind("<Button-3>", menu_exec_fuc)
    # 创建右键菜单2
    show_menu.add_command(label="Download",command=lambda: execute_download_command(treeview.item(treeview.focus())['values'][-1],treeview.item(treeview.focus())['text']))
    # 绑定右键点击事件2
    treeview.bind("<Button-3>", menu_download_fuc)
    # 绑定左键点击事件
    treeview.bind("<Button-1>", close_menu)
    # 运行窗口主循环
    window.mainloop()

if __name__ == "__main__":
    main()
