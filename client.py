#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import collections
import enum
import os
import re
import signal
import socket
import sys
import threading


netcov_pipe = "/tmp/netcovmap"
fuzzer_host = ("127.0.0.1", 5678)
RE_COVERAGE_LINE = re.compile("^(\w+):(\d+)=(.*)")
RE_EDGE_COUNT = re.compile("([\w\-.]+\+\d+)->([\w\-.]+\+\d+):(\d+);")
coverage_proxy = None


def sigint_handler(signal, frame):
    coverage_proxy.running = False


CoverageTrend = enum.Enum("CoverageTrend", ["EDGE_INCREASE", "EDGE_DECREASE", "STABLE"])


class CodeCoverage(object):
    def __init__(self):
        self.coverage_maps = collections.defaultdict(set)
        self._lock = threading.Lock()
        self.trend = CoverageTrend.STABLE
        self.delta = 0

    def get_trend(self):
        with self._lock:
            return self.trend, self.delta

    def update_trend(self, fd, current_map):
        with self._lock:
            previous_map = self.coverage_maps[fd]
            self.trend, self.delta = self.__get_coverage_trend(previous_map, current_map)
            if self.delta > 0:
                self.coverage_maps[fd] = current_map
            return self.trend, self.delta

    def __get_coverage_trend(self, previous_map, current_map):
        # Differences between previous and current set
        previous_diff = previous_map.difference(current_map)
        current_diff = current_map.difference(previous_map)

        # Total edge hitcount between differences. Catches cases where edges are identical, but edge hitcount differ
        # (e.g: a loop iterated further)
        previous_edge_hitcount = sum(map(lambda x: x[2], previous_diff))
        current_edge_hitcount = sum(map(lambda x: x[2], current_diff))

        delta = len(current_map - previous_map)
        if previous_map == current_map:
            state = CoverageTrend.STABLE
        elif previous_map > current_map:
            state = CoverageTrend.EDGE_DECREASE
        elif previous_map < current_map:
            state = CoverageTrend.EDGE_INCREASE
        else:
            delta = len(current_diff) - len(previous_diff)
            if delta > 0:
                state = CoverageTrend.EDGE_INCREASE
            elif delta < 0:
                state = CoverageTrend.EDGE_DECREASE
            else:
                state = CoverageTrend.STABLE
                delta = current_edge_hitcount - previous_edge_hitcount
        return state, delta


class CoverageProxy(threading.Thread):
    def __init__(self, pipe_name, socket_):
        self.pipe_name = pipe_name
        self.socket_ = socket_
        self.coverage = CodeCoverage()
        self.running = False
        super(CoverageProxy, self).__init__()

    @staticmethod
    def parse_coverage_packet(data):
        try:
            syscall, fd, coverage_info = RE_COVERAGE_LINE.match(data).groups()
            # Can't fail due to regexp match
            fd = int(fd)
            coverage_map = RE_EDGE_COUNT.findall(coverage_info)
            # Convert edge count to int. Construct a set based on the individual edges
            coverage_map = frozenset(map(lambda x: (x[0], x[1], int(x[2])), coverage_map))
        except AttributeError:
            raise ValueError("Invalid coverage trace: %s" % data)
        return syscall, fd, coverage_map

    def run(self):
        self.running = True
        with open(self.pipe_name, "r", encoding="ascii") as f:
            while self.running:
                line = f.readline()
                if line != "":
                    try:
                        syscall, fd, current_map = self.parse_coverage_packet(line)
                    except ValueError as ve:
                        # TODO: better error handling here
                        print(ve, file=sys.stderr)
                    else:
                        self.coverage.update_trend(fd, current_map)
                        state, delta = self.coverage.get_trend()

                        if state == CoverageTrend.EDGE_INCREASE:
                            print("Edge count increased by %d" % delta)
                        elif state == CoverageTrend.STABLE:
                            print("Edge count stable. Hit count changed by %d" % delta)
                        else:
                            print("Edge count decreased by %d" % delta)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint_handler)
    with socket.socket() as socket_:
        try:
            socket_.settimeout(5)
            socket_.connect(fuzzer_host)
        except socket.error as se:
            print("Unable to connect to %s: %s" % (fuzzer_host, se))
            exit(1)
        else:
            coverage_proxy = CoverageProxy(netcov_pipe, socket_)
            coverage_proxy.start()
            coverage_proxy.join()

