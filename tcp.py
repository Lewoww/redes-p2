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
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('Descartando segmento com "checksum" incorreto')
            return

        payload = segment[4*(flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no)

            numero_seq_inicial = random.randint(0, 0xffff)
            numero_ack_inicial = seq_no + 1

            segmento_resposta = make_header(dst_port, src_port, numero_seq_inicial, numero_ack_inicial, FLAGS_SYN | FLAGS_ACK)
            segmento_resposta = fix_checksum(segmento_resposta, dst_addr, src_addr)
            self.rede.enviar(segmento_resposta, src_addr)

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
        # Sequências e controle imediato
        self.seq_envio = random.randint(0, 0xffff)
        self.seq_no_eperado = seq_no + 1
        self.seq_no_comprimento = ack_no
        # Buffers e estado de envio
        self.seguimentos_enviados = deque()
        self.seguimentos_pendentes = deque()
        self.total_bytes_enviados = 0
        # Controle de janela
        self.tamanho_janela = 1 * MSS
        # Timer e tempo de retransmissão (usado após janela e envio serem definidos)
        self.timer = None
        self.TimeoutInterval = 1
        self.recalculo_timeout = False
        self.SampleRTT = 1
        self.EstimatedRTT = self.SampleRTT
        self.DevRTT = self.SampleRTT / 2

    def _temporizador(self):
        self.timer = None
        self.tamanho_janela /= 2

        if self.seguimentos_enviados:
            _, segmento, endereco_destino, tamanho_payload = self.seguimentos_enviados.popleft()[1:]
            self.seguimentos_enviados.appendleft((0, segmento, endereco_destino, tamanho_payload))
            self.servidor.rede.enviar(segmento, endereco_destino)
            self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._temporizador)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if (flags & FLAGS_FIN == FLAGS_FIN):
            self.callback(self, b'')
            self.seq_no_comprimento = ack_no
            src_addr, src_port, dst_addr, dst_port = self.id_conexao

            segmento_fin = make_header(dst_port, src_port, self.seq_envio, self.seq_no_eperado + 1, flags)
            resposta_fin = fix_checksum(segmento_fin, dst_addr, src_addr)
            self.servidor.rede.enviar(resposta_fin, src_addr)

        elif seq_no == self.seq_no_eperado:
            self.seq_no_eperado += len(payload) if payload else 0
            self.callback(self, payload)
            self.seq_no_comprimento = ack_no

            if (flags & FLAGS_ACK) == FLAGS_ACK:
                if payload:
                    src_addr, src_port, dst_addr, dst_port = self.id_conexao
                    segmento_ack = make_header(dst_port, src_port, self.seq_envio, self.seq_no_eperado, flags)
                    resposta_ack = fix_checksum(segmento_ack, dst_addr, src_addr)
                    self.servidor.rede.enviar(resposta_ack, src_addr)

                ha_segmentos_enviados = self.total_bytes_enviados > 0

                if self.timer:
                    self.timer.cancel()
                    self.timer = None

                    while self.seguimentos_enviados:
                        tempo_envio, segmento, _, tamanho_dados = self.seguimentos_enviados.popleft()
                        self.total_bytes_enviados -= tamanho_dados
                        seq_segmento = read_header(segmento)[2]
                        if seq_segmento == ack_no:
                            break
                            
                    if tempo_envio:
                        self.SampleRTT = time.time() - tempo_envio
                        if not self.recalculo_timeout:
                            self.recalculo_timeout = True
                            self.EstimatedRTT = self.SampleRTT
                            self.DevRTT = self.SampleRTT / 2
                        else:
                            self.EstimatedRTT = (1 - 0.125) * self.EstimatedRTT + 0.125 * self.SampleRTT
                            self.DevRTT = (1 - 0.25) * self.DevRTT + 0.25 * abs(self.SampleRTT - self.EstimatedRTT)
                        self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT

                nenhum_segmento_pendente = self.total_bytes_enviados == 0
                if ha_segmentos_enviados and nenhum_segmento_pendente:
                    self.tamanho_janela += MSS

                while self.seguimentos_pendentes:
                    segmento_esperado, endereco_destino, tamanho_dados = self.seguimentos_pendentes.popleft()

                    if self.total_bytes_enviados + tamanho_dados > self.tamanho_janela:
                        self.seguimentos_pendentes.appendleft((segmento_esperado, endereco_destino, tamanho_dados))
                        break

                    self.total_bytes_enviados += tamanho_dados
                    self.servidor.rede.enviar(segmento_esperado, endereco_destino)
                    self.seguimentos_enviados.append((time.time(), segmento_esperado, endereco_destino, tamanho_dados))

                if self.seguimentos_enviados:
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._temporizador)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        total_segmentos = ceil(len(dados) / MSS)

        for i in range(total_segmentos):
            self.seq_envio = self.seq_no_comprimento
            segmento = make_header(dst_port, src_port, self.seq_envio, self.seq_no_eperado, flags=FLAGS_ACK)
            segmento += dados[i * MSS : min((i + 1) * MSS, len(dados))]

            tamanho_dados = len(dados[i * MSS : min((i + 1) * MSS, len(dados))])
            self.seq_no_comprimento += tamanho_dados

            segmento_corrigido = fix_checksum(segmento, dst_addr, src_addr)

            if self.total_bytes_enviados + tamanho_dados <= self.tamanho_janela:
                self.servidor.rede.enviar(segmento_corrigido, src_addr)
                self.seguimentos_enviados.append((time.time(), segmento_corrigido, src_addr, tamanho_dados))
                self.total_bytes_enviados += tamanho_dados

                if not self.timer:
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._temporizador)
            else:
                self.seguimentos_pendentes.append((segmento_corrigido, src_addr, tamanho_dados))

    def fechar(self):
        self.seq_envio = self.seq_no_comprimento
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segmento_fin = make_header(dst_port, src_port, self.seq_envio, self.seq_no_eperado + 1, FLAGS_FIN)
        resposta_fin = fix_checksum(segmento_fin, dst_addr, src_addr)
        self.servidor.rede.enviar(resposta_fin, src_addr)
