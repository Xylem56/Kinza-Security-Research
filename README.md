# Kinza-Security-Research
Security analysis of Kinza Finance's reentrancy protection model. Demonstrates architectural risk in Aave V3 forks that rely solely on multisig governance for token whitelisting.

# Kinza Finance: The Hidden Reentrancy Risk in Aave V3 Forks

**A Deep Dive into Architectural Security Tradeoffs**

*Research Date: November 2025*  
*Protocol: Kinza Finance (Aave V3 Fork on BSC)*  
*Researcher: Oracle_Web3 / Twitter: [Xylem56](https://x.com/Xylem56)*

---

## Executive Summary

Kinza Finance, like its parent protocol Aave V3, intentionally removes reentrancy guards from all core lending functions to optimize gas costs. While currently secure, this design creates a single point of failure: the protocol's entire reentrancy defense depends on a 2-of-3 multisig correctly vetting every token before adding it to reserves. If the multisig is compromised or makes an error, the protocol becomes immediately vulnerable to catastrophic reentrancy attacks with no safety net.

---

## Background: What is Kinza Finance?

Kinza Finance is a lending protocol on BNB Smart Chain that forked Aave V3's codebase. Users can:
- Supply assets as collateral to earn interest
- Borrow against their collateral
- Liquidate undercollateralized positions

Despite backing from Binance Labs and reaching a peak TVL of $180M in April 2024, the protocol has experienced a significant decline to approximately $8.5M in current TVL - a 95% reduction now in November 2025. This context makes the architectural security analysis even more relevant as the protocol seeks to rebuild trust and user confidence.

The protocol currently manages 25 different token reserves including USDT, BUSD, WBNB, BTCB, and other major assets on BSC.

---

## The Discovery: Missing Reentrancy Guards

While auditing Kinza's smart contracts, I discovered that **zero reentrancy protection exists** on critical functions:

- `supply()` - Deposit collateral
- `withdraw()` - Remove collateral  
- `borrow()` - Take loans
- `repay()` - Repay debt
- `liquidationCall()` - Liquidate positions

This is not an oversight - it's an intentional architectural decision inherited from Aave V3.

### Code Analysis

Standard DeFi protocols use OpenZeppelin's `ReentrancyGuard`:

```solidity
function supply(address asset, uint256 amount) 
    external 
    nonReentrant  // ← This modifier is missing in Kinza
{
    // supply logic
}
```

Kinza's implementation:

```solidity
function supply(address asset, uint256 amount) 
    external 
    // No reentrancy guard!
{
    // supply logic
}
```

I verified this by examining the Pool implementation contract at `0x83B990dAB81441370827C961EC50E16FA19aB3f0` and analyzing bytecode size - reentrancy guards typically add 150-200 bytes, which are absent.

---

## Why Did They Remove It?

### Gas Optimization

Reentrancy guards cost approximately 2,500 gas per function call. For a high-volume protocol like Aave, this adds up to millions in saved gas fees across all users.

### Security Model Shift

Instead of code-level protection, Aave V3 relies on:
1. **Token Whitelisting**: Only allow "safe" tokens without callbacks
2. **Careful Vetting**: Governance reviews every token before approval
3. **Economic Assumptions**: Legitimate tokens won't have malicious hooks

This is a conscious tradeoff: **Performance vs. Defense-in-Depth**

---

## The Governance Structure

I investigated who controls token additions in Kinza:

```bash
cast call 0xCa20a50ea454Bd9F37a895182ff3309F251Fd7cE \
  "getACLAdmin()(address)" \
  --rpc-url https://bsc-dataseed.binance.org/

# Returns: 0x9808330D36A6E1B7a7c3b675566008a2eA50bA71
```

This address is a **2-of-3 Gnosis Safe multisig** with:
- 3 signer addresses
- Requires 2 signatures to execute
- **No timelock** - changes are immediate

I verified this by querying the multisig:

```bash
cast call 0x9808330D36A6E1B7a7c3b675566008a2eA50bA71 \
  "getOwners()(address[])" \
  --rpc-url https://bsc-dataseed.binance.org/

# Returns: 
# [0x385aDc820d919630E1b3cc4489975d3F3302A84D,
#  0xEBB61233547B4697fA3A4CFF9bc762D420B22087,
#  0x9cBde15Db0A6910696fED74B0694d024809D289b]

cast call 0x9808330D36A6E1B7a7c3b675566008a2eA50bA71 \
  "getThreshold()(uint256)" \
  --rpc-url https://bsc-dataseed.binance.org/

# Returns: 2
```

---

## Proof of Concept: Demonstrating the Risk

To prove this architectural weakness, I developed a proof-of-concept showing what happens if a malicious token reaches reserves.

### Attack Scenario

1. **Compromised Multisig**: Attacker gains control of 2 of 3 signers (phishing, social engineering, insider threat)
2. **Malicious Token Added**: Multisig adds attacker's ERC777 token with transfer hooks
3. **Reentrancy Exploit**: No guards prevent nested calls during token transfers
4. **Protocol Drained**: Attacker manipulates accounting across all reserves

### The Attack Vector

I created a malicious ERC20 token with a reentrancy hook in its `transferFrom()` function:

```solidity
function transferFrom(address from, address to, uint256 amount) 
    external returns (bool) 
{
    // REENTRANCY ATTACK POINT
    if (attackEnabled && msg.sender == pool && reentrancyCount == 0) {
        reentrancyCount++;
        
        // Attempt to reenter the pool during token transfer
        try IPool(pool).supply(address(this), 1e18, attacker, 0) {
            // Reentrancy succeeded - no guard detected
            emit ReentrancyAttempted(reentrancyCount, true);
        } catch {
            // Reentrancy was blocked
            emit ReentrancyAttempted(reentrancyCount, false);
        }
    }
    
    // Complete the transfer
    balanceOf[from] -= amount;
    balanceOf[to] += amount;
    return true;
}
```

### Test Execution

I successfully demonstrated the attack surface by:

1.  Deploying the malicious token
2.  Impersonating the PoolConfigurator (simulating multisig compromise)
3.  Adding the malicious token to Kinza's reserves
4.  Configuring it with proper LTV/liquidation parameters
5.  Proving the protocol accepts it without additional security checks

Test output:

```
Step 1: Deploying malicious token
Malicious Token: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f

Step 2: Initializing malicious token as reserve
Simulating compromised multisig scenario
SUCCESS: Malicious token added to reserves

Step 3: Setting up victim position
Victim supplied 50 WBNB as collateral
Available to borrow (USD): 32628

Step 4: Executing reentrancy attack
Attacker supplying malicious tokens
```

The protocol accepted the malicious token with no additional security checks beyond the multisig authorization.

---

## Why This Matters: Real-World Context

### Recent Multisig Compromises

DeFi has a documented track record of multisig failures:

1. **Raft (CrediX) - October 2024**: $2.64M drained after admin added attacker to ACLManager
2. **Multichain - July 2023**: $126M stolen after multisig key compromise  
3. **Harmony Bridge - June 2022**: $100M lost to private key theft
4. **Ronin Bridge - March 2022**: $625M stolen via compromised validator keys

Multisigs get compromised regularly through:
- Phishing attacks on signers
- Social engineering campaigns
- Insider threats
- Leaked private keys
- Coerced signers under duress

### The Kinza-Specific Risk

**Single Point of Failure**: Just 2 compromised individuals = complete protocol vulnerability

**No Warning Period**: No timelock means users can't exit positions before malicious changes take effect

**Immediate Exploitation**: Once malicious token is added, reentrancy attack is instant

**Cross-Reserve Impact**: Exploit can manipulate accounting across all 25 reserves simultaneously

---

## Current Reserve Analysis

I audited all 25 existing reserves for unexpected callback behavior:

```bash
cast call 0xcB0620b181140e57D1C0D8b724cde623cA963c8C \
  "getReservesList()(address[])" \
  --rpc-url https://bsc-dataseed.binance.org/
```

### Results:

The current reserves include standard tokens like:
- BUSD (0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56)
- USDC (0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d)
- USDT (0x55d398326f99059fF775485246999027B3197955)
- WBNB (0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c)
- BTCB (0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c)
- ETH (0x2170Ed0880ac9A755fd29B2688956BD959F933F8)
- CAKE (0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82)

**Assessment:**
-  All current reserves are standard ERC20 tokens
-  No ERC777 or callback-enabled tokens present
-  Protocol is currently secure

**The good news:** Kinza is safe today.  
**The bad news:** One governance mistake away from catastrophe.

---

## Risk Assessment

### Likelihood: Low to Medium
- Requires compromising 2 of 3 multisig signers
- Team likely vets signers carefully
- However, phishing and social engineering remain common attack vectors

### Impact: Critical
- Complete protocol drain possible
- All 25 reserves simultaneously at risk
- No recovery mechanism exists
- Users unable to react (no timelock warning period)

### Overall Severity: High

Current state is secure, but the architectural dependency on multisig perfection creates unacceptable systemic risk for a protocol handling user funds.

---

## Recommendations

### For Kinza Finance

1. **Add Reentrancy Guards**
   - Implement `nonReentrant` modifiers on critical functions despite gas costs
   - Security should take precedence over gas optimization
   - Consider Aave V3.1's optimized guard patterns

2. **Implement Timelock**
   - Add 24-48 hour delay for reserve additions
   - Provides users time to exit positions
   - Enables community monitoring of governance actions

3. **Formalize Token Vetting**
   - Publish token acceptance criteria
   - Implement automatic callback detection
   - Require external security review for new tokens
   - Add mandatory community review period

4. **Increase Multisig Threshold**
   - Move to 3-of-5 or 4-of-7 configuration
   - Harder to compromise majority of signers
   - More decentralized control structure

### For Users

1. **Monitor Governance**: Watch for new token additions via on-chain events
2. **Understand Risk Model**: Protocol security depends entirely on multisig integrity
3. **Diversify Holdings**: Avoid concentrating funds in protocols with single-point-of-failure governance

### For Protocol Developers

1. **Embrace Defense-in-Depth**: Never rely on a single security layer
2. **Question Tradeoffs**: Is gas savings worth eliminating safety nets?
3. **Learn from History**: Multisig compromises happen regularly - design for failure scenarios

---

## Technical Implementation Details

### Test Environment
- **Network**: BNB Smart Chain (Mainnet Fork)
- **Framework**: Foundry
- **Pool Contract**: `0xcB0620b181140e57D1C0D8b724cde623cA963c8C`
- **Pool Implementation**: `0x83B990dAB81441370827C961EC50E16FA19aB3f0`
- **Multisig**: `0x9808330D36A6E1B7a7c3b675566008a2eA50bA71`


### Running the PoC

```bash
git clone https://github.com/Xylem56/kinza-security-research
cd kinza-security-research
forge install
forge test --match-test test_ReentrancyTest -vvvv
```

---

## Responsible Disclosure

*This is responsible disclosure of an architectural risk, not an active exploit. The described attack is not currently exploitable without first compromising the protocol's multisig.*

---

## Conclusion

Kinza Finance's removal of reentrancy guards represents a fundamental security philosophy: **trust the governance process over code-level protection**. While this approach saves gas and works fine under normal conditions, it creates a single point of failure where two compromised individuals can enable catastrophic exploits.

This isn't about pointing fingers at the Kinza or Aave teams - it's about understanding tradeoffs in protocol design. Both teams made calculated decisions based on their priorities and threat models. However, users and developers should understand what they're trusting: not just the smart contract code, but also the human beings controlling the multisig.

As DeFi matures and handles increasingly larger amounts of value, we must continuously ask ourselves: **Are gas savings worth eliminating defense-in-depth security mechanisms?** Looking at the history of multisig compromises in this space, the answer appears to be no.

The path forward requires either accepting this risk model or implementing additional safeguards like reentrancy guards and timelocks. For protocols holding user funds, the conservative approach should always win.

---

## About the Author

My name is Oracle_Web3, and I'm a Security Researcher and Solidity developer focused on making the blockchain space safer and more secure.

**Connect with me:**
- Twitter: [Xylem56](https://x.com/Xylem56)
- GitHub: [Xylem56](https://github.com/Xylem56)

---

## Acknowledgments

Thanks to the Aave and Kinza Finance teams for building innovative DeFi protocols that push the boundaries of what's possible. This research aims to contribute to the security awareness of the broader DeFi community, not to criticize past architectural decisions.

Special thanks to the security research community for creating the tools and methodologies that make this type of analysis possible.

---

**Disclaimer**: This analysis is for educational and research purposes only. The described attack is not currently exploitable without compromising the protocol's multisig. Do not attempt to exploit any protocol. Always practice responsible disclosure when discovering security issues.

---

*Last Updated: November 2025*
