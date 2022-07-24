# Smart-Target

Smart Contract Security Vulnerability Detection Method based on Target-guided Symbolic 
Execution

## Dependencies
```shell
pip install solc-select==0.2.0
pip install timeout_decorator
pip install graphviz
pip install evm_cfg_builder
pip install slither-analyzer
pip install eth-hash==0.3.2
pip install loguru
```
and `mythril_target` in [Mythril-Target](https://github.com/yagol2020/Mythril-Target)
```shell
cd Mythril-Target
python setup.py install
```
check with `myth -v`

for exam analysis and output the exam result, should install..
```shell
pip install openpyxl
pip install pandas
pip install seaborn
```