import Auth
log = Auth.Auth()#'https://localhost:5678/')
#log.Name = str(input('username: '))
#log.Pass = str(input('password: '))
log.Name = str('max')
log.Pass = str('3008362')
yeah = str(input('l or s: '))
if yeah == 'l':
    print(log.Login())
elif yeah == 's':
    print(log.Signup())
load = str(input('load or save: '))
if load == 'l':
    print(log.Load('Data/fuck me/please/ong/buh/sdg'))
else:
    print(log.Save('Data/fuck me/please/ong/bruh/sdg', '42'))
#except Auth.UsernameError as err:
   # if str(err) == 'Username already exists':
        #log.Login()
    #else: raise Auth.UsernameError(err)
#log._Auth__User = 'MAX'
#log.Save(['brug'], 'this data is encrypted')
#print(log.Load(['brug']))
