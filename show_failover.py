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

from pathlib import Path

service_status = Path(f'/tmp/vyos-failover')
bestWeight = 0


def showRoute(route):
    print('\troute', route['name'], 'vrf',
          route['vrf'], 'table', route['table'])
    print('\t\tStatus:', ('up' if route['operational'] else 'down'))
    print('\t\tUCMP:', ('enabled' if route['ucmp'] else 'disabled'))
    for nexthop in route['next_hops']:
        print('')
        showNexthop(nexthop, route['ucmp'])
    print('')


def showNexthop(nexthop, ucmp):
    global bestWeight
    if nexthop['operational'] and nexthop['metric'] > bestWeight:
        bestWeight = nexthop['metric']

    print('\t\tnext-hop', nexthop['gateway'], 'local-address', nexthop['source'],
          'dev', nexthop['interface'], ('weight' if ucmp else 'metric'), nexthop['metric'])
    status = 'down'
    if nexthop['operational']:
        status = 'up'
        if ucmp and nexthop['metric'] < bestWeight:
            status = 'up (discarded)'
    print('\t\t\tStatus:', status)
    t = datetime.fromtimestamp(nexthop['last_change'])
    td = datetime.now()-t
    if nexthop['operational']:
        print('\t\t\tUptime:', duration(td))
    else:
        print('\t\t\tDowntime:', duration(td))
    print('\t\t\tSuccesses:', nexthop['success_count'])
    print('\t\t\tFailures:', nexthop['fail_count'])

    if not nexthop['operational'] and nexthop['check_fault'] != '':
        print('\t\t\tFault Description:')
        print('\t\t\t\t', nexthop['check_fault'])

    print('\t\t\tCheck Configuration:')
    print('\t\t\t\tType:', nexthop['check']['type'])
    print('\t\t\t\tTarget:', nexthop['check']['target'])
    print('\t\t\t\tInterval:', nexthop['check']['interval'])
    print('\t\t\t\tRTT Threshold:', nexthop['check']['rtt_threshold'])
    print('\t\t\t\tLoss Threshold:', nexthop['check']['loss_threshold'])

    print('\t\t\tPacket Loss:', "{}%".format(round(nexthop['packet_loss'], 2)))
    print('\t\t\tPackets Sent:', nexthop['packets_sent'])
    print('\t\t\tPackets Recv:', nexthop['packets_recv'])
    print('\t\t\tDuplicate Packets:', nexthop['packets_recv_dup'])

    print('\t\t\tMin RTT:', nexthop['min_rtt'])
    print('\t\t\tMax RTT:', nexthop['max_rtt'])
    print('\t\t\tAvg RTT:', nexthop['avg_rtt'])
    print('\t\t\tLatest RTT:', nexthop['last_rtt'])
    print('\t\t\tStdDev RTT:', nexthop['std_dev_rtt'])


def duration(td):
    days = td.days
    hours, rm = divmod(td.seconds, 3600)
    minutes, seconds = divmod(rm, 60)

    if (days != 0):
        return "%d days %d hours %d minutes %d seconds" % (days, hours, minutes, seconds)
    elif (hours != 0):
        return "%d hours %d minutes %d seconds" % (hours, minutes, seconds)
    elif (minutes != 0):
        return "%d minutes %d seconds" % (minutes, seconds)
    else:
        return "%d seconds" % (seconds)


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
        if args.route != None and args.route != route['route']:
            continue
        showRoute(route)
