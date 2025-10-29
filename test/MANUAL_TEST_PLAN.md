# Test Plan: Manual Testing of PeerWallet.initKeyPair

TODO: Automate these tests

## 1. No Key File Exists (First Run)
**Action:**  
Run the demo with a non-existent key file path.

**Expected:**  
- The CLI prompts the user on how to proceed (generate, restore, import).

---

## 2. Generate New Keypair (Option 1)
**Action:**  
- Choose option 1 (generate new keypair).
- Accept default derivation path.
- Leave password blank.
- Store the generated address for future reference

**Expected:**  
- A new mnemonic is generated and displayed.
- The derivation path used is displayed.
- The keypair is generated and exported to file.
- The CLI confirms success.

---

## 3. Reload generated Keystore
**Action:**  
- Run manual test again
- Open previously generated keystore (no password)

**Expected:**  
- The correct address is displayed
- The default derivation path used is displayed.
- The CLI confirms success.


---

## 4. Generate New Keypair (Option 1)
**Action:**  
- Choose option 1 (generate new keypair).
- Input a custom derivation path.
- Enter a password.
- after the file is created, restart the program
- Try to open with a wrong password
- Finally, open with the correct password

**Expected:**  
- A new mnemonic is generated and displayed.
- The derivation path used is displayed.
- The keypair is generated and exported to file.
- You cannot open the file with an incorrect password
- You can open the file with the valid password
- The CLI confirms success.

---

## 5. Restore from Mnemonic (Option 2)
**Action:**  
- Choose option 2.
- Enter the following mnemonic:
  - squirrel oven another neutral bamboo bean artist render daughter chalk trial island swap material helmet dose cheap citizen mom bird bulk ten rifle arctic 
- Enter the following derivation path:
  - m/918'/0'/0'/1'
- Enter a password

**Expected:**  
- The wallet is restored with the correct address and public key.
  - Address: trac1u5mz72x3mh7sej0vjhpqm34kuylwupj3mvlpevqn473l0fy7ukfsl4snx6
  - Public Key: e5362f28d1ddfd0cc9ec95c20dc6b6e13eee0651db3e1cb013afa3f7a49ee593
- The keypair is exported to file.
- The CLI confirms success.

---

## 5. Import from File (Option 3)
**Action:**  
- Choose option 3.
- Enter the path to the previously created keypair file.
- Enter the correct password.

**Expected:**  
- The wallet is loaded from file.
- The address and public key match the file’s data.
- The CLI confirms success.

---

## 6. Import from File with Wrong Password
**Action:**  
- Choose option 3.
- Enter the path to an existing keypair file.
- Enter an incorrect password 3 times.

**Expected:**  
- The CLI displays an error about the wrong password.
- After 3 failed attempts, import is aborted and user is prompted to choose an option between generating a new file, recovering from mnemonic or giving another filepath
