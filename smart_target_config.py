# 以下文件和合约, 因为无法分析的缘故, 在任何实验中都被跳过
SKIP_SOL_CONTRACT_NAME_PAIR = [
    ("unchecked_low_level_calls", "0x663e4229142a27f00bafb5d087e1e730648314c3","GeneScienceInterface", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls", "0x19cf8481ea15427a98ba3cdd6d9e14690011ab10","MigrationAgent", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls", "0xe09b1ab8111c2729a76f16de96bc86a7af837928","ERC20Interface", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls","0x663e4229142a27f00bafb5d087e1e730648314c3", "ERC721", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls","0x663e4229142a27f00bafb5d087e1e730648314c3", "ERC20", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls","0x19cf8481ea15427a98ba3cdd6d9e14690011ab10", "ERC20", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls", "0x19cf8481ea15427a98ba3cdd6d9e14690011ab10","tokenRecipient", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls", "0x7d09edb07d23acb532a82be3da5c17d9d85806b4","ERC20Interface", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls","0x52d2e0f9b01101a59b38a3d05c80b7618aeed984", "Token", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls", "0xec329ffc97d75fe03428ae155fc7793431487f63", "Token", "cfg error"),  # interface , 没有函数的实现
    ("unchecked_low_level_calls", "0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e", "ERC20Interface", "cfg error"),  # interface , 没有函数的实现
    ("access_control", "parity_wallet_bug_2","WalletAbi", "cfg error"),  # interface , 没有函数的实现
    ("reentrancy", "spank_chain_payment","LedgerChannel", "ASM策略"),
    ("reentrancy", "spank_chain_payment","Token", "cfg error"),  # interface , 没有函数的实现
    ("arithmetic", "BECToken", "ERC20", "cfg error"),  # interface , 没有函数的实现
    ("arithmetic", "BECToken","ERC20Basic", "cfg error"),  # interface , 没有函数的实现
    ("bad_randomness", "smart_billions","BasicToken", "cfg error"),  # 继承了interface
    ("bad_randomness", "smart_billions","ERC20", "cfg error"),  # interface , 没有函数的实现
    ("bad_randomness", "smart_billions","ERC20Basic", "cfg error"),  # interface , 没有函数的实现
    ("bad_randomness", "smart_billions","StandardToken", "cfg error"),  # 继承了interface
]