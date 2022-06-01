'''
Created on 23 May 2014

@author: christian
'''
import os

if os.name == 'nt':
    from bitcoinlib.entropy.perfmon import get_perfmon_data
    from bitcoinlib.entropy.performance_counter import get_performance_counter

    def get_system_entropy():
        """ return a list of tuples suitable for ssl_RAND_add
            (data, entropy_estimate)
            entropy_estimate is in bytes.
        """
        perfmon = get_perfmon_data()
        perf_counter = get_performance_counter()
        return ((perfmon, len(perfmon) / 100.0),
                (perf_counter, 1))
else:
    def get_system_entropy():
        pass
