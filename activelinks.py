import  volatility . plugins . common  as  common
import  volatility . plugins . registry . registryapi  as  registryapi
import  volatility . utils  as  utils
import  volatility . win32  as  win32
 
class  ActiveLinks(common.AbstractWindowsCommand):
         """ Get ActiveP list T """
         def  __init__( self ,  config ,  *args ,  **kwargs ):
                 common.AbstractWindowsCommand.__init__( self ,  config ,  *args ,  **kwargs )
                 self._config.add_option ( 'Search' , short_option = 't' , default = None , help = 'Ac Point Search For', action = 'store' )
         def  calculate(self):
                 addr_space = utils.load_as(self._config)
                 tasks = win32.tasks.pslist(addr_space)
                 T  =  self._config.Search
                 return T , tasks
         def  render_text( self ,  outfd ,  data ):
                 T , tas = data
                 try :
                         ishex  = T.find("0x")
                         ishex2 = T.find("0X")
                         if(ishex>-1 or ishex2>-1 ):
                                 T = int(T, 16)
                         else :
                                 T = int(T)
                         for i in tas :
                                 AcLin = i.ActiveProcessLinks
                                 if T == AcLin :
                                         print (i.ImageFileName)
                 except :
                         print("ActiveProcessLinks is a memory location : use number" )