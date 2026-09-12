import base64,json,re,time
from pathlib import Path
from genlayer_py import create_client,create_account
from genlayer_py.chains import studionet

ROOT=Path(__file__).parents[1]
ADDRESS='0x0A2cd11D0a59B844bC9993D62404ec02E292c21A'
TXS={'deployment':'0x140a6039c14864db2e0e611c7c87c2fa376305d6371c0afbae31c42a35d65445','queue':'0x57236ed722aace1069242f67a6f484f2a574bd0e6dbd1947db0de3089486dcf0','screen':'0x58b6661fec352787d26b93c9d3f20f3c38971afc59810af1b05c3fa8037ff7ff'}
SCAN='FIXTURE-1789230833'
env=(ROOT.parents[3]/'accounts.env').read_text();key=re.search(r'^ACCOUNT_2_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)',env,re.M).group(1).strip();account=create_account(account_private_key=key);client=create_client(chain=studionet,account=account)
def execution(tx):
 receipts=(tx.get('consensus_data') or {}).get('leader_receipt') or []
 return receipts[0].get('execution_result') if receipts else None
def main():
 deadline=time.time()+420;records={}
 while True:
  records={name:client.get_transaction(transaction_hash=value) for name,value in TXS.items()}
  if all(item.get('status_name')=='FINALIZED' for item in records.values()):break
  if time.time()>deadline:raise RuntimeError('transactions did not finalize in time')
  time.sleep(10)
 deployed=base64.b64decode(records['deployment']['data']['contract_code']).decode();local=(ROOT/'contracts'/'contract.py').read_text();scan=client.read_contract(address=ADDRESS,function_name='get_scan',args=[SCAN])
 out={'contract':ADDRESS,'wallet':account.address,'walletMatchesOwner':scan['owner'].lower()==account.address.lower(),'sourceMatches':deployed==local,'scan':{'id':SCAN,'state':scan['state'],'verdict':scan['verdict'],'digestCount':len(scan['digests'])},'transactions':{name:{'hash':TXS[name],'status':tx.get('status_name'),'execution':execution(tx)} for name,tx in records.items()}}
 assert out['walletMatchesOwner'] and out['sourceMatches'] and out['scan']['state']=='FINAL' and out['scan']['digestCount']==3 and all(t['status']=='FINALIZED' and t['execution']=='SUCCESS' for t in out['transactions'].values())
 print(json.dumps(out,indent=2))
if __name__=='__main__':main()
