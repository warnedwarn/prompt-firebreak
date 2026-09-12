import json,re
from pathlib import Path
from genlayer_py import create_client,create_account
from genlayer_py.chains import studionet
root=Path(__file__).parents[1]
env=(root.parents[3]/'accounts.env').read_text()
key=re.search(r'^ACCOUNT_2_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)',env,re.M).group(1).strip()
client=create_client(chain=studionet,account=create_account(account_private_key=key))
tx=client.deploy_contract(code=(root/'contracts'/'contract.py').read_text(),args=[])
print('deploy_tx='+str(tx),flush=True)
receipt=client.wait_for_transaction_receipt(transaction_hash=tx,status='ACCEPTED',retries=120,interval=10000)
address=receipt.get('data',{}).get('contract_address') or receipt.get('to_address') or receipt.get('recipient')
if not address:raise RuntimeError('deployment address missing')
print(json.dumps({'contract':address,'deploymentTx':tx,'network':'StudioNet','result':receipt.get('result_name'),'status':receipt.get('status_name')},default=str),flush=True)
