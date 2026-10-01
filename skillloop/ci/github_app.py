"""Scoped GitHub App client; credentials and installation tokens stay in memory."""
import base64,json,re,subprocess,time,urllib.request
from skillloop.protocol import digest_jcs


def check_identity(repository,pr,head_sha,config_digest):
    if not re.fullmatch('[0-9a-f]{40}',head_sha):raise ValueError('invalid_head_sha')
    return digest_jcs([repository,pr,head_sha,config_digest])


class GitHubApp:
    def __init__(self,config):
        self.repository=config['repository'];self.app_id=config['app_id']
        def enc(data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
        now=int(time.time());unsigned=enc(b'{"alg":"RS256","typ":"JWT"}')+'.'+enc(json.dumps({'iat':now-60,'exp':now+540,'iss':str(self.app_id)},separators=(',',':')).encode())
        signature=subprocess.run(['openssl','dgst','-sha256','-sign',config['private_key_path']],input=unsigned.encode(),capture_output=True)
        if signature.returncode:raise ValueError('app_signing_failed')
        jwt=unsigned+'.'+enc(signature.stdout)
        install=self._request('/app/installations/'+str(config['installation_id']),jwt)
        if install['app_id']!=self.app_id:raise ValueError('installation_app_mismatch')
        self.token=self._request('/app/installations/'+str(config['installation_id'])+'/access_tokens',jwt,'POST',{'repositories':[self.repository.split('/')[1]],'permissions':{'checks':'write','contents':'read','pull_requests':'read'}})['token']

    @staticmethod
    def _request(path,token,method='GET',body=None):
        req=urllib.request.Request('https://api.github.com'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=30) as response:return json.load(response)

    def request(self,path,method='GET',body=None):
        return self._request('/repos/'+self.repository+path,self.token,method,body)

    def ensure_pending_check(self,pr,config_digest):
        head=self.request('/pulls/'+str(pr))['head']['sha']
        identity=check_identity(self.repository,pr,head,config_digest)
        existing=self.request('/commits/'+head+'/check-runs?per_page=100')['check_runs']
        matching=[c for c in existing if c.get('external_id')==identity and c['app']['id']==self.app_id]
        if len(matching)>1:raise ValueError('duplicate_check_identity')
        check=matching[0] if matching else self.request('/check-runs','POST',{'name':'SkillLoop synthetic integration','head_sha':head,'external_id':identity,'status':'in_progress','output':{'title':'Integration experiment; qualification pending','summary':'Synthetic CI fixture. No Skill qualification is asserted by this check.'}})
        return {'head_sha':head,'identity':identity,'check_id':check['id'],'created':not bool(matching)}
