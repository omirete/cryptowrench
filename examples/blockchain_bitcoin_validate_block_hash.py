import requests
from cryptowrench.blockchain.bitcoin import validate_block_hash

chain = 'main'
block_hash = '100000'
url = f'https://api.blockcypher.com/v1/btc/{chain}/blocks/{block_hash}'

response = requests.get(url)
if response.status_code == 200:
    results = response.json()

    is_valid = validate_block_hash(
        version=results["ver"],
        hash_previous_block=results['prev_block'],
        hash_merkle_root=results['mrkl_root'],
        time=results["time"],
        bits=int(results["bits"]),
        nonce=results["nonce"]
    )

    if is_valid:
        print('Block hash meets the target.')
    else:
        print('Block hash does not meet the target.')
else:
    print(response.text)