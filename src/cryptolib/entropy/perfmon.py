import os

if os.name == 'nt':
    import winreg

    def get_perfmon_data():
        value, type = winreg.QueryValueEx(winreg.HKEY_PERFORMANCE_DATA, "Global")
        return value

if __name__ == '__main__':

    print(get_perfmon_data()[0:100].encode("hex"))
