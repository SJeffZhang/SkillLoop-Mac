"""Scoped GitHub App client; credentials and installation tokens stay in memory."""
import base64,json,re,subprocess,time,urllib.request
from skillloop.protocol import digest_jcs


def check_identity(repository,pr,head_sha,config_digest,generation=None):
    if not re.fullmatch('[0-9a-f]{40}',head_sha):raise ValueError('invalid_head_sha')
    if generation is None:
        # Preserve the identity of historical transport-only integration checks.
        return digest_jcs([repository,pr,head_sha,config_digest])
    if type(generation) is not int or not 1<=generation<=9007199254740991:
        raise ValueError('invalid_qualification_generation')
    return digest_jcs([repository,pr,head_sha,config_digest,generation])


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

    def ensure_qualification_check(self,*,pr,head_sha,config_digest,generation):
        """Create one generation-bound formal Check after an exact live PR read.

        A completed Check is returned only as an original receipt. The caller
        must verify its current qualification and may not reopen it as pending.
        """
        if type(pr) is not int or pr<1:
            raise ValueError('invalid_pull_request')
        identity=check_identity(self.repository,pr,head_sha,config_digest,generation)
        observed=self.request('/pulls/'+str(pr))
        if observed['head']['sha']!=head_sha:
            raise ValueError('stale_head')
        matches=[]
        for page in range(1,11):
            batch=self.request('/commits/'+head_sha+'/check-runs?per_page=100&page='+str(page))['check_runs']
            matches.extend(c for c in batch if c.get('external_id')==identity
                           and c.get('app',{}).get('id')==self.app_id)
            if len(batch)<100:break
        else:
            raise ValueError('check_inventory_pagination_limit')
        if len(matches)>1:raise ValueError('duplicate_check_identity')
        if matches:
            check=matches[0]
            if (check.get('head_sha')!=head_sha or check.get('name')!='SkillLoop qualification'
                    or check.get('status') not in {'in_progress','completed'}):
                raise ValueError('qualification_check_original_state')
        else:
            check=self.request('/check-runs','POST',{
                'name':'SkillLoop qualification','head_sha':head_sha,'external_id':identity,
                'status':'in_progress','output':{
                    'title':'Qualification pending independent review',
                    'summary':'The current campaign has not issued a qualification decision.'}})
        if (check.get('head_sha')!=head_sha or check.get('external_id')!=identity
                or check.get('app',{}).get('id')!=self.app_id):
            raise ValueError('qualification_check_actual_app_binding')
        if self.request('/pulls/'+str(pr))['head']['sha']!=head_sha:
            raise ValueError('stale_head_after_check_creation')
        return {'head_sha':head_sha,'identity':identity,'check_id':check['id'],
                'generation':generation,'status':check['status'],'created':not bool(matches)}

    def complete_integration_check(self,pr,receipt,current_config):
        if self.request('/pulls/'+str(pr))['head']['sha']!=receipt['head_sha']:
            raise ValueError('stale_head')
        identity=check_identity(self.repository,pr,receipt['head_sha'],current_config)
        if receipt['identity']!=identity:raise ValueError('stale_configuration')
        check=self.request('/check-runs/'+str(receipt['check_id']))
        if check['head_sha']!=receipt['head_sha'] or check.get('external_id')!=identity or check['app']['id']!=self.app_id:
            raise ValueError('check_identity_mismatch')
        return self.request('/check-runs/'+str(receipt['check_id']),'PATCH',{'status':'completed','conclusion':'neutral','output':{'title':'Synthetic integration transport verified','summary':'This receipt tests App transport only. It does not grant Skill qualification.'}})
