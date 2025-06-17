# Privacy-Preserving-Identification-Using-Hash-Tree-and-zk-SNARKs

## For the benchmark we have considered:

We compared three different credential types with 12 claims each: VC1 (Residence Card), VC2 (Passport), and VC3 (Driving Licence).  Selectively, the VP is produced from these VCs.  We had four sets of claims ready.
TestFinal/updated_claims.json 


## Off-Chain Preprocessing:

![image](https://github.com/user-attachments/assets/938bd203-7610-4b4f-8946-b7720ce4ec0b)


![image](https://github.com/user-attachments/assets/782a3eb8-5232-41c9-95e8-c9c65fcd1423)

## Off-Chain Benchmarking:

![image](https://github.com/user-attachments/assets/4012da06-76a0-4125-b927-190ed3bad235)


## RSA: VC1, VC2:


![image](https://github.com/user-attachments/assets/5a53a29c-1acc-44d6-957a-68edf89bc768)

## EdDSA: VC3, VP
![image](https://github.com/user-attachments/assets/5fb865c6-abdc-420c-8969-1866df0a0cd1)


## reuseableVP.sol Smart conract deployment: 
![image](https://github.com/user-attachments/assets/6d7c7906-c79c-41a8-a1d2-07ef3dae276d)

### Register VC:
![image](https://github.com/user-attachments/assets/c7784676-e53f-4aa0-ab8f-6342e5a737bb)


### Verify VC VC:

![image](https://github.com/user-attachments/assets/91c48080-9664-459a-b8c8-b8392652dbce)


Compile and Computation of zkSNARKs.zok:
![image](https://github.com/user-attachments/assets/75971526-61ad-48f0-a9db-f663ce7a6375)

Successful setup of zkSNARKs:
![image](https://github.com/user-attachments/assets/8ead40f3-6f93-4534-98c9-729c33397778)

Successfully generationg the proof:
![image](https://github.com/user-attachments/assets/0db5cbf3-a716-4645-bf97-01b6257c3e8a)

Verifier.sol is ready now for on-chain verification:
![image](https://github.com/user-attachments/assets/63a9b83d-11f9-4d2b-a5a3-4f98cb305b38)

Deployment of verifier.sol:
![image](https://github.com/user-attachments/assets/1febec3b-49bf-416b-b4ca-79a7a9b3cafd)


Successful verification of proof:
![image](https://github.com/user-attachments/assets/605aa197-ea1b-4c65-b660-b35a10dd9959)




## Attack Vector:

![image](https://github.com/user-attachments/assets/173d9c3d-ac56-4190-8239-343daf1f0429)



