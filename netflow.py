import dshell
import netflowout


class DshellDecoder(dshell.TCPDecoder):

    def __init__(self):
        dshell.TCPDecoder.__init__(self,
                                   name='netflow',
                                   description='generate netflow information from pcap',
                                   longdescription='generate netflow information from pcap',
                                   filter='(tcp or udp)',
                                   author='bg',
                                   # grouping for output module
                                   optiondict={'group': dict()}
                                   )
        self.out = netflowout.NetflowOutput()

    def pre_module(self):
        # pass grouping to output module
        if self.group:
            self.out.group = self.group.split(',')
        dshell.TCPDecoder.preModule(self)

    def connection_handler(self, conn):
        self.alert(**conn.info())

    def post_module(self):
        self.out.close()  # write flow groups if grouping
        dshell.TCPDecoder.postModule(self)


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
