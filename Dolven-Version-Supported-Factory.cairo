
#       ___       __                __        __
#      / _ \___  / /  _____ ___    / /  ___ _/ /  ___
#     / // / _ \/ / |/ / -_) _ \  / /__/ _ `/ _ \(_-<
#    /____/\___/_/|___/\__/_//_/ /____/\_,_/_.__/___/
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_not_zero
from starkware.starknet.common.syscalls import get_caller_address, get_block_timestamp, deploy
from starkware.cairo.common.alloc import alloc

from starkware.cairo.common.bool import TRUE, FALSE
from openzeppelin.access.ownable import Ownable

@storage_var
func versions(category : felt, version : felt) -> (class_hash : felt):
end

@storage_var
func deployedContracts(category : felt, nonce : felt) -> (contract_address : felt):
end

# Category 1 -> Deploys Vault
# Category 2 -> Deploys Vester
# Category 3 -> Deploys Unstaker

@storage_var
func last_version_by_category(category : felt) -> (version : felt):
end

@storage_var
func salt() -> (current_salt : felt):
end

@storage_var
func contracts_by_category(category : felt) -> (contract_address : felt):
end

@storage_var
func deployer() -> (account : felt):
end

@event
func Created(address : felt, category : felt, timestamp : felt):
end

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    contract_class_hash : felt, category : felt
):
    alloc_locals
    let (caller) = get_caller_address()
    Ownable.initializer(caller)

    versions.write(category, 0, contract_class_hash)
    let last_version : felt = last_version_by_category.read(category)
    last_version_by_category.write(category, last_version)
    deployer.write(caller)
    return ()
end

# # Getters

@view
func get_deployed_contracts{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    category : felt
) -> (addresses_len : felt, addresses : felt*):
    let (addresses_len, addresses) = recursiveContractAddresses(0, category)
    return (addresses_len, addresses - addresses_len)
end

@view
func get_deployer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    deployer : felt
):
    let (_deployer : felt) = deployer.read()
    return (_deployer)
end

@view
func get_address_by_category{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    category : felt
) -> (address : felt):
    let (address : felt) = contracts_by_category.read(category)
    return (address)
end

@view
func get_salt{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    _salt : felt
):
    let (_salt : felt) = salt.read()
    return (_salt)
end

@view
func get_last_version_by_category{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}(category : felt) -> (address : felt):
    let (address : felt) = last_version_by_category.read(category)
    return (address)
end

# #External Functions

@external
func deployVaultContract{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    _stakingToken : felt,
    _poolToken : felt,
    _startTimestamp : felt,
    _finishTimestamp : felt,
    _poolTokenAmount : felt,
    _limitForTicket : felt,
    _isFarming : felt,
    version : felt,
):
    alloc_locals
    Ownable.assert_only_owner()
    # # Category 1
    let call_data_array : felt* = alloc()
    let _deployer : felt = deployer.read()
    assert call_data_array[0] = _stakingToken
    assert call_data_array[1] = _poolToken
    assert call_data_array[2] = _startTimestamp
    assert call_data_array[3] = _finishTimestamp
    assert call_data_array[4] = _poolTokenAmount
    assert call_data_array[5] = _limitForTicket
    assert call_data_array[6] = _isFarming
    assert call_data_array[7] = _deployer

    let _salt : felt = salt.read()
    let _lastVersion : felt = last_version_by_category.read(1)
    let _classHash : felt = versions.read(1, version)

    let (new_contract_address : felt) = deploy(
        class_hash=_classHash,
        contract_address_salt=_salt,
        constructor_calldata_size=8,
        constructor_calldata=call_data_array,
    )
    deployedContracts.write(1, _lastVersion, new_contract_address)
    contracts_by_category.write(1, new_contract_address)
    let (time) = get_block_timestamp()
    last_version_by_category.write(1, _lastVersion + 1)
    salt.write(_salt + 1)
    Created.emit(new_contract_address, 1, time)
    return ()
end

@external
func deployVestingContract{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    _saleToken : felt, version : felt
):
    alloc_locals
    Ownable.assert_only_owner()
    # # Category 2
    let call_data_array : felt* = alloc()
    let _deployer : felt = deployer.read()
    assert call_data_array[0] = _saleToken
    assert call_data_array[1] = _deployer

    let _salt : felt = salt.read()
    let _lastVersion : felt = last_version_by_category.read(2)
    let _classHash : felt = versions.read(2, version)

    let (new_contract_address : felt) = deploy(
        class_hash=_classHash,
        contract_address_salt=_salt,
        constructor_calldata_size=2,
        constructor_calldata=call_data_array,
    )
    deployedContracts.write(2, _lastVersion, new_contract_address)
    contracts_by_category.write(2, new_contract_address)
    let (time) = get_block_timestamp()
    last_version_by_category.write(2, _lastVersion + 1)
    salt.write(_salt + 1)
    Created.emit(new_contract_address, 2, time)
    return ()
end

@external
func deployUnstakerContract{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    token_address_ : felt, staking_contract_address_ : felt, version : felt
):
    alloc_locals
    Ownable.assert_only_owner()
    # # Category 2
    let call_data_array : felt* = alloc()
    let _deployer : felt = deployer.read()
    assert call_data_array[0] = staking_contract_address_
    assert call_data_array[1] = token_address_
    assert call_data_array[2] = _deployer

    let _salt : felt = salt.read()
    let _lastVersion : felt = last_version_by_category.read(3)
    let _classHash : felt = versions.read(3, version)

    let (new_contract_address : felt) = deploy(
        class_hash=_classHash,
        contract_address_salt=_salt,
        constructor_calldata_size=3,
        constructor_calldata=call_data_array,
    )
    deployedContracts.write(3, _lastVersion, new_contract_address)
    contracts_by_category.write(3, new_contract_address)
    let (time) = get_block_timestamp()
    last_version_by_category.write(3, _lastVersion + 1)
    salt.write(_salt + 1)
    Created.emit(new_contract_address, 3, time)
    return ()
end

# # Internal Functions

func recursiveContractAddresses{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address_nonce : felt, category : felt
) -> (addresses_len : felt, addresses : felt*):
    alloc_locals
    let addressCount : felt = last_version_by_category.read(category)
    let contract_address : felt = deployedContracts.read(2, address_nonce)
    if addressCount == address_nonce:
        let (found_addresses : felt*) = alloc()
        return (0, found_addresses)
    end

    let (
        address_memory_location_len, addresss_memory_location : felt*
    ) = recursiveContractAddresses(address_nonce + 1, category)
    assert [addresss_memory_location] = contract_address
    return (address_memory_location_len + 1, addresss_memory_location + 1)
end

