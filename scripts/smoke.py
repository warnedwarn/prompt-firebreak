import json,re,time
from pathlib import Path
from genlayer_py import create_client,create_account
from genlayer_py.chains import studionet

ROOT=Path(__file__).parents[1]
ADDRESS='0x0A2cd11D0a59B844bC9993D62404ec02E292c21A'
env=(ROOT.parents[3]/'accounts.env').read_text()
key=re.search(r'^ACCOUNT_2_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)',env,re.M).group(1).strip()
account=create_account(account_private_key=key)
client=create_client(chain=studionet,account=account)
scan='FIXTURE-'+str(int(time.time()))
sources=['https://www.iana.org/domains/reserved','https://www.rfc-editor.org/rfc/rfc2606.txt','https://example.com/']
queue=client.write_contract(address=ADDRESS,function_name='queue_scan',args=[scan,'Extract the reserved documentation domain names explicitly identified by these technical fixture records.','{"reserved_domains":["string"],"purpose":"string"}',sources],value=0)
qr=client.wait_for_transaction_receipt(transaction_hash=queue,status='ACCEPTED',retries=120,interval=5000)
screen=client.write_contract(address=ADDRESS,function_name='screen',args=[scan,300],value=0)
sr=client.wait_for_transaction_receipt(transaction_hash=screen,status='ACCEPTED',retries=120,interval=5000)
record=client.read_contract(address=ADDRESS,function_name='get_scan',args=[scan])
print(json.dumps({'wallet':account.address,'scanId':scan,'queueTx':queue,'queueStatus':qr.get('status_name'),'queueResult':qr.get('result_name'),'screenTx':screen,'screenStatus':sr.get('status_name'),'screenResult':sr.get('result_name'),'state':record['state'],'verdict':record['verdict'],'riskCodes':record['risk_codes'],'digestCount':len(record['digests'])},indent=2,default=str),flush=True)
