import asyncio
from collections import deque
from math import ceil
import random
import time
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('Descartando segmento com "checksum" incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no)
            numero_seq_envio = random.randint(0, 0xffff)
            numero_ack_envio = seq_no + 1
            segment_header = make_header(dst_port, src_port, numero_seq_envio, numero_ack_envio, FLAGS_SYN | FLAGS_ACK)
            response = fix_checksum(segment_header, dst_addr, src_addr)
            self.rede.enviar(response, src_addr)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.numero_seq_envio = random.randint(0, 0xffff)
        self.numero_seq_esperado = seq_no + 1
        self.numero_seq_comprimento = ack_no
        self.fila_segmentos_enviados = deque()
        self.fila_segmentos_esperando = deque()
        self.comprimento_segmentos_enviados = 0
        self.window_size = 1 * MSS
        self.checado = False
        self.SampleRTT = 1
        self.EstimatedRTT = self.SampleRTT
        self.DevRTT = self.SampleRTT / 2
        self.TimeoutInterval = 1
        self.timer = None

    def _timer(self):
        self.timer = None
        self.window_size = self.window_size / 2

        if self.fila_segmentos_enviados:
            segmento, endereco, comprimento_dados = self.fila_segmentos_enviados.popleft()[1:]
            self.fila_segmentos_enviados.appendleft((0, segmento, endereco, comprimento_dados))
            self.servidor.rede.enviar(segmento, endereco)
            self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._timer)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if (flags & FLAGS_FIN == FLAGS_FIN):
            self.callback(self, b'')
            self.numero_seq_comprimento = ack_no
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            segment = make_header(dst_port, src_port, self.numero_seq_envio, self.numero_seq_esperado + 1, flags)
            response = fix_checksum(segment, dst_addr, src_addr)
            self.servidor.rede.enviar(response, src_addr)

        elif seq_no == self.numero_seq_esperado:
            self.numero_seq_esperado += (len(payload) if payload else 0)
            self.callback(self, payload)
            self.numero_seq_comprimento = ack_no

            if (flags & FLAGS_ACK) == FLAGS_ACK:
                if payload:
                    src_addr, src_port, dst_addr, dst_port = self.id_conexao
                    segment = make_header(dst_port, src_port, self.numero_seq_envio, self.numero_seq_esperado, flags)
                    response = fix_checksum(segment, dst_addr, src_addr)
                    self.servidor.rede.enviar(response, src_addr)
                existe_fila_segmentos_esperando = self.comprimento_segmentos_enviados > 0
                
                if self.timer:
                    self.timer.cancel()
                    self.timer = None

                    while self.fila_segmentos_enviados:
                        primeiroTempo, segment, _, comprimento_dados = self.fila_segmentos_enviados.popleft()
                        self.comprimento_segmentos_enviados -= comprimento_dados
                        seq = read_header(segment)[2]
                        if seq == ack_no:
                            break

                    if primeiroTempo:
                        self.SampleRTT = time.time() - primeiroTempo
                        if self.checado == False:
                            self.checado = True
                            self.EstimatedRTT = self.SampleRTT
                            self.DevRTT = self.SampleRTT / 2
                        else:
                            self.EstimatedRTT = (1 - 0.125) * self.EstimatedRTT + 0.125 * self.SampleRTT
                            self.DevRTT = (1 - 0.25) * self.DevRTT + 0.25 * abs(self.SampleRTT - self.EstimatedRTT)
                        self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT
                nenhum_comprimento_segmentos_enviados = self.comprimento_segmentos_enviados == 0
                
                if existe_fila_segmentos_esperando and nenhum_comprimento_segmentos_enviados:
                    self.window_size += MSS

                while self.fila_segmentos_esperando:
                    response, endereco, comprimento_dados = self.fila_segmentos_esperando.popleft()

                    if self.comprimento_segmentos_enviados + comprimento_dados > self.window_size:
                        self.fila_segmentos_esperando.appendleft((response, endereco, comprimento_dados))
                        break
                    self.comprimento_segmentos_enviados += comprimento_dados
                    self.servidor.rede.enviar(response, endereco)
                    self.fila_segmentos_enviados.append((time.time(), response, endereco, comprimento_dados))

                if self.fila_segmentos_enviados:
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._timer)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        tamanho = ceil(len(dados) / MSS)
        
        for i in range(tamanho):
            self.numero_seq_envio = self.numero_seq_comprimento
            segment = make_header(dst_port, src_port, self.numero_seq_envio, self.numero_seq_esperado, flags=FLAGS_ACK)
            segment += (dados[ i * MSS : min((i + 1) * MSS, len(dados))])
            comprimento_dados = len(dados[i * MSS : min((i + 1) * MSS, len(dados))])
            self.numero_seq_comprimento += comprimento_dados
            response = fix_checksum(segment, dst_addr, src_addr)
            
            if self.comprimento_segmentos_enviados + comprimento_dados <= self.window_size:
                self.servidor.rede.enviar(response, src_addr)
                self.fila_segmentos_enviados.append((time.time(), response, src_addr, comprimento_dados))
                self.comprimento_segmentos_enviados += comprimento_dados
                
                if not self.timer:
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._timer)
            else:
                self.fila_segmentos_esperando.append((response, src_addr, comprimento_dados))

    def fechar(self):
        self.numero_seq_envio = self.numero_seq_comprimento
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segment = make_header(dst_port, src_port, self.numero_seq_envio, self.numero_seq_esperado + 1, FLAGS_FIN)
        response = fix_checksum(segment, dst_addr, src_addr)
        self.servidor.rede.enviar(response, src_addr)
