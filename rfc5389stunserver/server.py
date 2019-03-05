#!/usr/bin/env python3

import logging
import socket
import threading

from rfc5389stunserver.constants import MsgClass, MethodType, AttrType
from rfc5389stunserver.stunattributes.xor_mapped_address import XorMappedAddress
from rfc5389stunserver.stun_header import STUNHeader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def udp_thread(server: socket, address: tuple, data: bytes):
    '''
    メッセージを受信
    最初の00やmagic cookieの値の正当性を確かめる
    メッセージ長、メソッドとクラスの正当性
    fingerprintを使ってる場合、その正しさ
    エラーがある場合はただ捨てる
    認証チェック
    '''
    # headerの中身をごにょごにょして残りの長さを求める
    header, payload = data[0: 20], data[20:]
    req_stun_header = STUNHeader.fromBin(header)
    print(f'Header is {header.hex()}')
    print(f'Address is {address}')
    logger.info(f'Header length is {req_stun_header.message_length}')
    logger.info(f'Maggic cookie is {req_stun_header.magic_cookie.hex()}')
    logger.info(f'Transaction ID is {req_stun_header.transaction_id.hex()}')

    xma = XorMappedAddress(
        address[1], address[0], req_stun_header.transaction_id)
    res_stun_header = STUNHeader(req_stun_header.transaction_id,
                                 MsgClass.SUCCESS_RESPONSE,
                                 MethodType.BINDING)
    res_stun_header.message_length = 4 + xma.length

    server.sendto(res_stun_header.bin + xma.bin, address)

    if len(payload) > 0:
        index = 0
        while index < len(payload):
            logger.info('---STUN Attr---')
            attr_type = int.from_bytes(payload[index:index+2], 'big')
            attr_len = int.from_bytes(payload[index+2:index+4], 'big')
            try:
                logger.info(f'AttrType: {AttrType(attr_type)}')
            except ValueError:
                logger.error(f'AttrType: Unknown ({attr_type})')
            logger.info(f'Length: {attr_len}')
            index += 4 + attr_len + (4 - attr_len % 4) % 4


def create_udp_server(PORT: int):
    server = socket.socket(socket.AF_INET | socket.AF_INET6,
                           socket.SOCK_DGRAM)
    try:
        server.bind((socket.gethostname(), PORT))
    except socket.gaierror:
        server.bind(('', PORT))
    logger.info('UDP server: Start listening')

    while True:
        # Receive data from someone
        (data, address) = server.recvfrom(16384)  # 長さは適当
        th = threading.Thread(
            target=udp_thread, args=([server, address, data]))
        th.start()


def create_udp_server_thread(PORT: int):
    th = threading.Thread(target=create_udp_server, args=([PORT]))
    th.start()
    return th
