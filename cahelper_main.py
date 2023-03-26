#!/usr/bin/python
# coding: utf-8

#+--------------------------------------------------------------------
#|   CAHelper 1.0
#|   By xieyi1393<xieyi@cnitai.com>
#+--------------------------------------------------------------------
import sys,os,json
import re
#设置运行目录
os.chdir("/www/server/panel")

#添加包引用位置并引用公共包
sys.path.append("class/")
import public
from OpenSSL import crypto
#from common import dict_obj
#get = dict_obj();


#在非命令行模式下引用面板缓存和session对象
if __name__ != '__main__':
    from BTPanel import cache,session

    #设置缓存(超时10秒) cache.set('key',value,10)
    #获取缓存 cache.get('key')
    #删除缓存 cache.delete('key')

    #设置session:  session['key'] = value
    #获取session:  value = session['key']
    #删除session:  del(session['key'])
def props(obj):
    pr = {}
    for name in dir(obj):
        value = getattr(obj, name)
        if not name.startswith('__') and not callable(value) and not name.startswith('_'):
            pr[name] = value
    return pr
def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False
class cahelper_main:
    __plugin_path = "/www/server/panel/plugin/cahelper/"
    __config = None

    #构造方法
    def  __init__(self):
        pass

    #自定义访问权限检查
    #一但声明此方法，这意味着可以不登录面板的情况下，直接访问此插件，由_check方法来检测是否有访问权限
    #如果您的插件必需登录后才能访问的话，请不要声明此方法，这可能导致严重的安全漏洞
    #如果权限验证通过，请返回True,否则返回 False 或 public.returnMsg(False,'失败原因')
    #示例未登录面板的情况下访问get_logs方法： /demo/get_logs.json  或 /demo/get_logs.html (使用模板)
    #获取面板日志列表
    #示例已登录面板的情况下访问get_logs方法：/plugin?action=a&name=demo&s=get_logs
    #示例未登录的情况下通过模板输出： /demo/get_logs.html
    #示例未登录的情况下输出JSON： /demo/get_logs.json

    def getDeatil(self,args):
        return {"result":{"version": public.ExecShell("openssl version")},"status":3}
        
        
    def genRSA(self,args):
        return {"result":{"prikey": public.ExecShell("openssl genrsa 4096")[0]},"status":2,"msg":"秘钥生成成功!"}
        
    def addCA(self,args):
        if not 'C' in args:return {"status":0,"msg":"必填项不能为空!"}
        if not 'ST' in args:return {"status":0,"msg":"必填项不能为空!"}
        if not 'CT' in args:return {"status":0,"msg":"必填项不能为空!"}
        if not 'O' in args:return {"status":0,"msg":"必填项不能为空!"}
        if not 'OU' in args:return {"status":0,"msg":"必填项不能为空!"}
        if not 'CN' in args:return {"status":0,"msg":"必填项不能为空!"}
        if not 'emailAddress' in args:return {"status":0,"msg":"必填项不能为空!"}
        if args.C.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.ST.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.CT.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.O.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.OU.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.CN.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.emailAddress.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        
        if args.C.find("/")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.ST.find("/")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.CT.find("/")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.O.find("/")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.OU.find("/")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.CN.find("/")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.emailAddress.find("/")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        caId=public.GetRandomString(24)
        public.ExecShell("mkdir /www/ca/ca/"+caId+"/")
        public.ExecShell("mkdir /www/ca/ca/"+caId+"/private/")
        public.ExecShell("mkdir /www/ca/ca/"+caId+"/newcerts/")
        public.ExecShell("mkdir /www/ca/ca/"+caId+"/crl/")
        public.ExecShell("mkdir /www/ca/ca/"+caId+"/certs/")
        public.ExecShell("touch /www/ca/ca/"+caId+"/index.txt")
        public.ExecShell("echo \"00\">/www/ca/ca/"+caId+"/serial")
        public.ExecShell("echo \"00\">/www/ca/ca/"+caId+"/crlnumber")
        public.ExecShell("openssl genrsa -out /www/ca/ca/"+caId+"/private/cakey.pem 4096")
        public.ExecShell("openssl req  -new -key /www/ca/ca/"+caId+"/private/cakey.pem -out /www/ca/ca/"+caId+"/careq.csr -subj \"/C="+args.C+"/ST="+args.ST+"/O="+args.O+"/OU="+args.OU+"/CN="+args.CN+"/emailAddress="+args.emailAddress+"\" -config /www/server/panel/plugin/cahelper/ca_gen.cnf -utf8")
        public.ExecShell("openssl x509 -req -days 36500 -in /www/ca/ca/"+caId+"/careq.csr -signkey /www/ca/ca/"+caId+"/private/cakey.pem -out /www/ca/ca/"+caId+"/cacert.pem")
        cert_file = "/www/ca/ca/"+caId+"/cacert.pem"
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
        subject = cert.get_subject()
        if not subject.CN==args.CN:
            return {"status":1,"msg":"创建CA失败!"}
        return {"status":2,"msg":"创建CA成功!"}
    def signcert(self,args):
        if not 'caId' in args:return {"status":0,"msg":"必填项不能为空!"}
        if not 'type' in args:return {"status":0,"msg":"必填项不能为空!"}
        if not 'csr' in args:return {"status":0,"msg":"必填项不能为空!"}
        if args.caId.find("/")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.caId.find(".")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.AIAAddress.find("\n")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.AIAAddress.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.CRLAddress.find("\n")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.CRLAddress.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.CPSAddress.find("\n")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.CPSAddress.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.MutiDomain.find("\n")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        if args.MutiDomain.find("\"")>=0:return {"status":0,"msg":"参数中含有非法字符!"}
        customExt="";
        custonCnf="";
        if 'CPSAddress' in args:
            customExt+="\ncertificatePolicies=@crtpolicy\n"
            custonCnf+="[crtpolicy]\nCPS.1=\""+args.CPSAddress+"\"\n";
        if 'AIAAddress' in args:
            customExt+="authorityInfoAccess=@aiaInfo\n"
            custonCnf+="[aiaInfo]\ncaIssuers;URI.0 = \""+args.AIAAddress+"\"\n";
        if 'MutiDomain' in args:
            customExt+="subjectAltName=@dnsNames\n"
            custonCnf+="[dnsNames]\n"
            MutiArray=args.MutiDomain.split(",")
            cfgCount=1
            for i in MutiArray:
                if not i=="":
                    sPreName="DNS"
                    if isIP(i):
                        sPreName="IP"
                    custonCnf+=sPreName+"."+str(cfgCount)+"=\""+i+"\"\n"
                    cfgCount=cfgCount+1
        if 'CRLAddress' in args:
            customExt+="crlDistributionPoints=@crlOpt\n"
            custonCnf+="\n[crlOpt]\nURI.1=\""+args.CRLAddress+"\"\n"
        caconfig = open("/www/server/panel/plugin/cahelper/ca.cnf").read()
        confTplPath={"serverCert":"/www/server/panel/plugin/cahelper/conf_tpl/serverCert.tpl","clientCert":"/www/server/panel/plugin/cahelper/conf_tpl/clientCert.tpl","codeSign":"/www/server/panel/plugin/cahelper/conf_tpl/codeSign.tpl","secondCaCert":"/www/server/panel/plugin/cahelper/conf_tpl/secondCa.tpl",}.get(args.type,"/www/server/panel/plugin/cahelper/conf_tpl/serverCert.tpl");
        tplDATA = open(confTplPath).read()
        caconfig=caconfig.replace("{{dir}}","/www/ca/ca/"+args.caId+"/")
        caconfig=caconfig.replace("{{certCFG}}",tplDATA+"\n"+customExt+"\n"+custonCnf)
        certUID=public.GetRandomString(36)
        cfgh=open("/tmp/"+certUID+".cfg","w")
        cfgh.write(caconfig)
        cfgh.close()
        csrh=open("/tmp/"+certUID+".csr","w")
        csrh.write(args.csr)
        csrh.close()
        dat=public.ExecShell("openssl ca -in \"/tmp/"+certUID+".csr\" -out \"/tmp/"+certUID+".pem\" -config \"/tmp/"+certUID+".cfg\" -batch")
        if open("/tmp/"+certUID+".pem").read()=="":
            return {"status":0,"msg":"签发证书失败!","errInfo":dat}
        w1 = '-----BEGIN CERTIFICATE-----'
        w2 = '-----END CERTIFICATE-----'
        dt=open("/tmp/"+certUID+".pem").read()
        pat = re.compile(w1+'(.*?)'+w2,re.S)
        #public.ExecShell("rm -f /tmp/"+certUID+".cfg");
        #public.ExecShell("rm -f /tmp/"+certUID+".pem");
        return {"status":1,"msg":"签发证书成功!","result":pat.findall(dt)}

    def getCAs(self,args):
        res=[];
        for i in os.listdir("/www/ca/ca/"):
            temp_dir = os.path.join("/www/ca/ca/", i)
            if os.path.isdir(temp_dir):
                cert_file = "/www/ca/ca/"+i+"/cacert.pem"
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
                subject = cert.get_subject()
                res.append({"id":i,"subj":subject.CN});
        return {"status":3,"result":res}

    #读取配置项(插件自身的配置文件)
    #@param key 取指定配置项，若不传则取所有配置[可选]	
    #@param force 强制从文件重新读取配置项[可选]
    def __get_config(self,key=None,force=False):
        #判断是否从文件读取配置
        if not self.__config or force:
            config_file = self.__plugin_path + 'config.json'
            if not os.path.exists(config_file): return None
            f_body = public.ReadFile(config_file)
            if not f_body: return None
            self.__config = json.loads(f_body)

        #取指定配置项
        if key:
            if key in self.__config: return self.__config[key]
            return None
        return self.__config

    #设置配置项(插件自身的配置文件)
    #@param key 要被修改或添加的配置项[可选]
    #@param value 配置值[可选]
    def __set_config(self,key=None,value=None):
        #是否需要初始化配置项
        if not self.__config: self.__config = {}

        #是否需要设置配置值
        if key:
            self.__config[key] = value

        #写入到配置文件
        config_file = self.__plugin_path + 'config.json'
        public.WriteFile(config_file,json.dumps(self.__config))
        return True

