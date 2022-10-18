#!/usr/bin/env python3
#
# Copyright (C) 2022 VyOS maintainers and contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
from datetime import datetime
import math

from pathlib import Path

service_status = Path(f'/tmp/vyos-failover')


def showRoute(route):
    col1 = 13
    print('\troute', route['route'])
    print('\t\tStatus:', ('up' if route['operational'] else 'down'))
    print('\t\tMultipath:', ('yes' if route['multipath'] else 'no'))
    for nexthop in route['next_hops']:
        showNexthop(nexthop, route['multipath'])
        print('')

    print('')


def showNexthop(nexthop, multipath):
    col1 = 13
    col2 = 17
    print('\t\tnext-hop', nexthop['gateway'], 'local-address', nexthop['source'],
          'dev', nexthop['interface'], ('weight' if multipath else 'metric'), nexthop['metric'])
    print('\t\t\tStatus:', ('up' if nexthop['operational'] else 'down'))
    t = datetime.fromtimestamp(nexthop['last_change'])
    td = datetime.now()-t
    if nexthop['operational']:
        print('\t\t\tUptime:', duration(td))
    else:
        print('\t\t\tDowntime:', duration(td))
    print('\t\t\tSuccesses:', nexthop['success_count'])
    print('\t\t\tFailures:', nexthop['fail_count'])

    print('\t\t\tIP-SLA Check:')
    print('\t\t\t\tTarget:', nexthop['check']['target'])
    print('\t\t\t\tInterval:', nexthop['check']['interval'])
    print('\t\t\t\tRTT Threshold:', nexthop['check']['rtt_threshold'])
    print('\t\t\t\tLoss Threshold:', nexthop['check']['loss_threshold'])

    print('\t\t\tPackets Sent:', nexthop['packets_sent'])
    print('\t\t\tPackets Recv:', nexthop['packets_recv'])
    print('\t\t\tDuplicate Packets:', nexthop['packets_recv_dup'])
    print('\t\t\tPacket Loss:', nexthop['packet_loss'], '%')

    print('\t\t\tLatest RTT:', nexthop['last_rtt'])
    print('\t\t\tMin RTT:', nexthop['min_rtt'])
    print('\t\t\tMax RTT:', nexthop['max_rtt'])
    print('\t\t\tAvg RTT:', nexthop['avg_rtt'])
    print('\t\t\tStdDev RTT:', nexthop['std_dev_rtt'])


def duration(td):
    elapsedTime = td.seconds
    hours = math.floor(elapsedTime / (60*60))
    elapsedTime = elapsedTime - hours * (60*60)
    minutes = math.floor(elapsedTime / 60)
    elapsedTime = elapsedTime - minutes * (60)
    seconds = math.floor(elapsedTime)
    elapsedTime = elapsedTime - seconds
    ms = elapsedTime * 1000
    if (hours != 0):
        return "%d hours %d minutes %d seconds" % (hours, minutes, seconds)
    elif (minutes != 0):
        return "%d minutes %d seconds" % (minutes, seconds)
    elif (seconds != 0):
        return "%d seconds %f ms" % (seconds, ms)
    else:
        return "%f ms" % (ms)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--route", type=str, help='Route to inspect')
    args = parser.parse_args()

    try:
        config = json.loads(service_status.read_text())
    except Exception as err:
        print(
            f'Data file "{service_status}" does not exist or malformed: {err}'
        )
        exit(1)

    print('Failover Routes:')
    for route in config:
        showRoute(route)