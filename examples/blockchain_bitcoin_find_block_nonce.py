import requests
from cryptowrench.blockchain.bitcoin import find_block_nonce


chain = 'main'
block_hash_or_height = '10'
url = f'https://api.blockcypher.com/v1/btc/{chain}/blocks/{block_hash_or_height}'

response = requests.get(url)
if response.status_code == 200:
    results = response.json()
    
    result = find_block_nonce(
        version=results["ver"],
        hash_previous_block=results["prev_block"],
        hash_merkle_root=results["mrkl_root"],
        time=results["time"],
        bits=results["bits"]
    )

    if result != False:
        magic_nonce = result
        print(magic_nonce)
    else:
        print('No nonce meets the target difficulty for the given block configuration.')

else:
    print(response.text)


# H(s,x,c) < 2^(n-k)