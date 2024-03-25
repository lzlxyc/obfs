"""Zeek log to Pandas Dataframe Example"""
from __future__ import print_function
import os
import sys
import argparse

# Local imports
from zat.log_to_dataframe import LogToDataFrame
BRO_CSV_DIR = "../bro_trace_csv"
if not os.path.exists(BRO_CSV_DIR):
    os.makedirs(BRO_CSV_DIR)



if __name__ == '__main__':
    # Example to populate a Pandas dataframe from a zeek log reader

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    # parser.add_argument('../data/conn.log', type=str, help='Specify a zeek log to run ZeekLogReader test on')
    args, commands = parser.parse_known_args()

    source_dir = 'Z:/.other/test/obfs-detection/data'
    in_data_list = ['conn.log','http.log','ssl.log']
    out_data_list = ['obfs4.pcap_flow_meta.csv','obfs4.pcap_flow_http.csv','obfs4.pcap_flow_ssl.csv']

    for idx, in_path in enumerate(in_data_list):
        zeek_log = os.path.join(source_dir,in_path)
        save_path = os.path.join(BRO_CSV_DIR, out_data_list[idx])
        # Check for unknown args
        if commands:
            print('Unrecognized args: %s' % commands)
            sys.exit(1)

        # File may have a tilde in it
        if zeek_log:
            zeek_log = os.path.expanduser(zeek_log)

            # Create a Pandas dataframe from a Zeek log
            log_to_df = LogToDataFrame()
            zeek_df = log_to_df.create_dataframe(zeek_log)

            # Print out the head of the dataframe
            print(zeek_df.head())
            zeek_df.to_csv(save_path,encoding='utf-8-sig')

            # Print out the types of the columns
            print(zeek_df.dtypes)

            # Print out size and memory usage
            print('DF Shape: {:s}'.format(str(zeek_df.shape)))
            print('DF Memory:')
            memory_usage = zeek_df.memory_usage(deep=True)
            total = memory_usage.sum()
            for item in memory_usage.items():
                print('\t {:s}: \t{:.2f} MB'.format(item[0], item[1]/1e6))
            print('DF Total: {:.2f} GB'.format(total/(1e9)))
