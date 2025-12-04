import streamlit as st
from web3 import Web3
import requests
import networkx as nx
from pyvis.network import Network
from pycoingecko import CoinGeckoAPI
from dotenv import load_dotenv
import os
import pandas as pd
import logging
import numpy as np
import json
from datetime import datetime
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

class TroubleshootingUtilities:
    """
    Utilities for troubleshooting common blockchain investigation issues
    """
    
    @staticmethod
    def validate_ethereum_address(address):
        """
        Validate Ethereum address format and checksum
        """
        issues = []
        
        if not address:
            issues.append(("EMPTY_ADDRESS", "No address provided"))
            return False, issues
        
        # Check basic format (0x + 40 hex chars)
        if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
            issues.append(("INVALID_FORMAT", "Address must be 0x followed by 40 hexadecimal characters"))
            return False, issues
        
        # Check checksum if mixed case
        if any(c.isupper() for c in address[2:]):
            try:
                checksum_address = Web3.to_checksum_address(address)
                if checksum_address != address:
                    issues.append(("CHECKSUM_MISMATCH", 
                                 f"Checksum mismatch. Try using: {checksum_address}"))
                    return False, issues
            except ValueError as e:
                issues.append(("CHECKSUM_ERROR", f"Checksum validation failed: {str(e)}"))
                return False, issues
        
        return True, issues
    
    @staticmethod
    def suggest_common_issues(address):
        """
        Suggest common issues based on address characteristics
        """
        suggestions = []
        
        # Check if it might be a contract address
        try:
            w3 = Web3(Web3.HTTPProvider(os.getenv('INFURA_API_URL', '')))
            code = w3.eth.get_code(Web3.to_checksum_address(address))
            if len(code) > 2:
                suggestions.append("This appears to be a contract address. Contracts typically have different transaction patterns.")
        except Exception:
            pass
        
        # Check if it's a known exchange address (might have many internal txs)
        known_exchanges = [
            "0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE",  # Binance hot wallet
            "0x28C6c06298d514Db089934071355E5743bf21d60",  # Binance cold wallet
            "0xDFd5293D8e347dFe59E90eFd55b2956a1343963d",  # Coinbase
            "0xE92d1A43df510F82C66382592a047d288f85226f"   # Kraken
        ]
        
        if address in known_exchanges:
            suggestions.append("This is a known exchange address. Exchange addresses often have complex transaction patterns that may require specialized analysis.")
        
        # Check for testnet patterns
        testnet_addresses = [
            "0x0000000000000000000000000000000000000000",  # Zero address
            "0x1111111111111111111111111111111111111111",  # Pattern address
        ]
        
        if address in testnet_addresses:
            suggestions.append("This appears to be a test pattern address, not a real user address.")
        
        return suggestions
    
    @staticmethod
    def check_api_status():
        """
        Check status of external APIs
        """
        api_status = {}
        
        # Check Etherscan API
        try:
            test_params = {
                'module': 'stats',
                'action': 'ethsupply',
                'apikey': os.getenv('ETHERSCAN_API_KEY', 'YourApiKeyToken')
            }
            response = requests.get("https://api.etherscan.io/api", params=test_params, timeout=10)
            api_status['etherscan'] = {
                'status': 'OK' if response.status_code == 200 else 'ERROR',
                'status_code': response.status_code
            }
        except Exception as e:
            api_status['etherscan'] = {
                'status': 'ERROR',
                'error': str(e)
            }
        
        # Check CoinGecko API
        try:
            cg = CoinGeckoAPI()
            response = cg.ping()
            api_status['coingecko'] = {
                'status': 'OK' if response.get('gecko_says') else 'ERROR',
                'response': response
            }
        except Exception as e:
            api_status['coingecko'] = {
                'status': 'ERROR',
                'error': str(e)
            }
        
        return api_status
    
    @staticmethod
    def get_alternative_endpoints():
        """
        Get alternative API endpoints for transaction data
        """
        return {
            'etherscan_alternative': 'https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address={address}&tag=latest&apikey={api_key}',
            'alchemy': 'https://eth-mainnet.g.alchemy.com/v2/{api_key}',
            'infura': 'https://mainnet.infura.io/v3/{api_key}',
            'moralis': 'https://deep-index.moralis.io/api/v2/{address}/erc20/transfers'
        }

class ForensicHeuristics:
    """
    Advanced forensic heuristics for blockchain transaction analysis
    Implements pattern recognition for common illicit activities
    """
    
    # Common mixer/hub addresses (example - should be updated with real data)
    MIXER_ADDRESSES = [
        "0x7FF9cFad3877F21d41Da6E5d5d1f5C1D4E1aD2e3",  # Example Tornado Cash
        "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",  # Example Wasabi
        "0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc"   # Example mixer
    ]
    
    # Common exchange addresses (for reference)
    EXCHANGE_ADDRESSES = [
        "0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE",  # Binance hot wallet
        "0x28C6c06298d514Db089934071355E5743bf21d60",  # Binance cold wallet
        "0xDFd5293D8e347dFe59E90eFd55b2956a1343963d",  # Coinbase
        "0xE92d1A43df510F82C66382592a047d288f85226f"   # Kraken
    ]
    
    @staticmethod
    def detect_peeling_chain(transactions):
        """
        Detect peeling chain pattern (structured transactions)
        Common in money laundering where funds are moved through multiple addresses
        """
        suspicious_patterns = []
        
        # Group by sender
        sender_groups = transactions.groupby('from')
        
        for sender, group in sender_groups:
            if len(group) > 3:  # Multiple transactions from same sender
                # Check for similar amounts sent to different addresses
                amounts = group['value'].astype(float)
                if amounts.nunique() == 1:  # All same amount
                    suspicious_patterns.append({
                        'pattern': 'PEELING_CHAIN',
                        'address': sender,
                        'transaction_count': len(group),
                        'amount': float(amounts.iloc[0]),
                        'risk_score': min(80, len(group) * 15)
                    })
        
        return suspicious_patterns
    
    @staticmethod
    def detect_coinjoin_pattern(transactions, timeframe_hours=24):
        """
        Detect potential CoinJoin mixing patterns
        Multiple inputs, multiple outputs with similar amounts
        """
        suspicious = []
        
        # Group transactions by time window
        if 'timestamp' in transactions.columns:
            transactions['timestamp_dt'] = pd.to_datetime(transactions['timestamp'], unit='s')
            transactions['time_window'] = transactions['timestamp_dt'].dt.floor(f'{timeframe_hours}H')
            
            for window, group in transactions.groupby('time_window'):
                if len(group) > 5:
                    # Check for many-to-many pattern
                    unique_senders = group['from'].nunique()
                    unique_receivers = group['to'].nunique()
                    
                    if unique_senders > 2 and unique_receivers > 2:
                        # Check for similar amounts (within 10%)
                        amounts = group['value'].astype(float)
                        amount_std = amounts.std()
                        amount_mean = amounts.mean()
                        
                        if amount_std / amount_mean < 0.1:  # Low variance
                            suspicious.append({
                                'pattern': 'COINJOIN_SUSPECTED',
                                'time_window': str(window),
                                'transaction_count': len(group),
                                'unique_senders': unique_senders,
                                'unique_receivers': unique_receivers,
                                'amount_mean': float(amount_mean),
                                'amount_std': float(amount_std),
                                'risk_score': 70
                            })
        
        return suspicious
    
    @staticmethod
    def detect_mixer_interaction(address, transactions):
        """
        Check for interactions with known mixer addresses
        """
        interactions = []
        
        # Check if address sent to known mixer
        sent_to_mixer = transactions[transactions['to'].isin(ForensicHeuristics.MIXER_ADDRESSES)]
        if not sent_to_mixer.empty:
            interactions.append({
                'type': 'SENT_TO_MIXER',
                'mixer_addresses': sent_to_mixer['to'].tolist(),
                'transaction_count': len(sent_to_mixer),
                'total_amount': float(sent_to_mixer['value'].astype(float).sum()),
                'risk_score': 90
            })
        
        # Check if address received from known mixer
        received_from_mixer = transactions[transactions['from'].isin(ForensicHeuristics.MIXER_ADDRESSES)]
        if not received_from_mixer.empty:
            interactions.append({
                'type': 'RECEIVED_FROM_MIXER',
                'mixer_addresses': received_from_mixer['from'].tolist(),
                'transaction_count': len(received_from_mixer),
                'total_amount': float(received_from_mixer['value'].astype(float).sum()),
                'risk_score': 85
            })
        
        return interactions
    
    @staticmethod
    def detect_rapid_movement(transactions, timeframe_minutes=10):
        """
        Detect rapid movement of funds (potentially structuring)
        """
        suspicious = []
        
        if 'timestamp' in transactions.columns:
            # Sort by timestamp
            txs_sorted = transactions.sort_values('timestamp')
            txs_sorted['timestamp_dt'] = pd.to_datetime(txs_sorted['timestamp'], unit='s')
            
            # Calculate time differences
            txs_sorted['time_diff'] = txs_sorted['timestamp_dt'].diff().dt.total_seconds() / 60
            
            # Find clusters of rapid transactions
            rapid_clusters = []
            current_cluster = []
            
            for idx, row in txs_sorted.iterrows():
                if len(current_cluster) == 0:
                    current_cluster.append(row)
                elif row['time_diff'] < timeframe_minutes:
                    current_cluster.append(row)
                else:
                    if len(current_cluster) >= 3:
                        rapid_clusters.append(current_cluster)
                    current_cluster = [row]
            
            for cluster in rapid_clusters:
                total_amount = sum(float(tx['value']) for tx in cluster)
                suspicious.append({
                    'pattern': 'RAPID_MOVEMENT',
                    'transaction_count': len(cluster),
                    'timeframe_minutes': timeframe_minutes,
                    'total_amount': total_amount,
                    'risk_score': min(75, len(cluster) * 20)
                })
        
        return suspicious
    
    @staticmethod
    def detect_round_trip(transactions, address):
        """
        Detect round-trip transactions (sending to self through intermediates)
        """
        suspicious = []
        
        # Create directed graph
        G = nx.DiGraph()
        for _, tx in transactions.iterrows():
            G.add_edge(tx['from'], tx['to'], value=float(tx['value']))
        
        # Look for cycles involving the target address
        try:
            cycles = list(nx.simple_cycles(G))
            for cycle in cycles:
                if address in cycle and len(cycle) <= 4:  # Short cycles are suspicious
                    # Calculate total amount in cycle
                    cycle_amount = 0
                    for i in range(len(cycle)):
                        sender = cycle[i]
                        receiver = cycle[(i + 1) % len(cycle)]
                        if G.has_edge(sender, receiver):
                            cycle_amount += G[sender][receiver]['value']
                    
                    suspicious.append({
                        'pattern': 'ROUND_TRIP',
                        'cycle': cycle,
                        'cycle_length': len(cycle),
                        'estimated_amount': cycle_amount,
                        'risk_score': 60
                    })
        except nx.NetworkXNoCycle:
            # No cycles found, which is normal
            pass
        
        return suspicious

def forensic_rubric(graph, known_bad_addresses=None, transaction_values=None, address_metadata=None):
    """
    Enhanced forensic rubric with multiple risk dimensions
    """
    if known_bad_addresses is None:
        known_bad_addresses = []
    if transaction_values is None:
        transaction_values = []
    if address_metadata is None:
        address_metadata = {}
    
    scores = {'dimensions': {}}
    
    # 1. Network Centrality Analysis
    if graph.number_of_nodes() > 0:
        centrality = nx.degree_centrality(graph)
        avg_centrality = np.mean(list(centrality.values()))
        scores['dimensions']['centrality_risk'] = {
            'score': min(avg_centrality * 1000, 100),
            'description': 'High degree indicates potential hub/mixer',
            'avg_centrality': float(avg_centrality)
        }
    else:
        scores['dimensions']['centrality_risk'] = {'score': 0, 'description': 'No graph data'}
    
    # 2. Proximity to Known Bad Addresses
    bad_proximity_score = 0
    proximity_details = []
    if known_bad_addresses and graph.number_of_nodes() > 0:
        for bad_addr in known_bad_addresses:
            if bad_addr in graph.nodes():
                # Calculate average distance to bad address
                distances = []
                for node in graph.nodes():
                    if nx.has_path(graph, node, bad_addr):
                        try:
                            dist = nx.shortest_path_length(graph, node, bad_addr)
                            distances.append(dist)
                        except nx.NetworkXNoPath:
                            continue
                if distances:
                    avg_dist = np.mean(distances)
                    proximity_score = 100 / (avg_dist + 1)
                    proximity_details.append({
                        'bad_address': bad_addr,
                        'avg_distance': float(avg_dist),
                        'score_contribution': float(proximity_score)
                    })
                    bad_proximity_score = max(bad_proximity_score, proximity_score)
    
    scores['dimensions']['bad_proximity'] = {
        'score': bad_proximity_score,
        'details': proximity_details,
        'description': 'Closeness to known illicit addresses'
    }
    
    # 3. Transaction Pattern Analysis
    if transaction_values:
        # Volume analysis
        mean_vol = np.mean(transaction_values)
        std_vol = np.std(transaction_values)
        max_vol = np.max(transaction_values)
        
        volume_score = min((mean_vol / 1e6 + std_vol / 1e6 + max_vol / 1e7) * 10, 100)
        
        scores['dimensions']['volume_analysis'] = {
            'score': float(volume_score),
            'mean_volume': float(mean_vol),
            'std_volume': float(std_vol),
            'max_volume': float(max_vol)
        }
    
    # 4. Clustering Coefficient
    if graph.number_of_nodes() > 1:
        try:
            clustering = nx.average_clustering(graph.to_undirected())
            scores['dimensions']['clustering'] = {
                'score': clustering * 100,
                'coefficient': float(clustering),
                'description': 'High clustering may indicate coordinated activity'
            }
        except nx.NetworkXError:
            scores['dimensions']['clustering'] = {'score': 0, 'description': 'Could not compute clustering'}
    
    # 5. Transaction Graph Complexity
    if graph.number_of_nodes() > 0:
        # Assortativity (similar nodes connect to similar nodes)
        try:
            assortativity = nx.degree_assortativity_coefficient(graph)
            scores['dimensions']['assortativity'] = {
                'score': abs(assortativity) * 50,  # Both high positive and negative can be suspicious
                'value': float(assortativity),
                'description': 'Non-random connection patterns'
            }
        except nx.NetworkXError:
            pass
    
    # Calculate overall score (weighted average)
    dimension_scores = [d['score'] for d in scores['dimensions'].values() if isinstance(d, dict) and 'score' in d]
    if dimension_scores:
        # Weight certain dimensions more heavily
        weights = {
            'bad_proximity': 2.0,
            'centrality_risk': 1.5,
            'volume_analysis': 1.2,
            'default': 1.0
        }
        
        weighted_sum = 0
        total_weight = 0
        
        for dim_name, dim_data in scores['dimensions'].items():
            if isinstance(dim_data, dict) and 'score' in dim_data:
                weight = weights.get(dim_name, weights['default'])
                weighted_sum += dim_data['score'] * weight
                total_weight += weight
        
        overall_score = weighted_sum / total_weight if total_weight > 0 else 0
    else:
        overall_score = 0
    
    scores['overall_risk'] = float(overall_score)
    
    # Risk classification
    if overall_score >= 80:
        scores['risk_level'] = 'CRITICAL'
    elif overall_score >= 60:
        scores['risk_level'] = 'HIGH'
    elif overall_score >= 40:
        scores['risk_level'] = 'MEDIUM'
    elif overall_score >= 20:
        scores['risk_level'] = 'LOW'
    else:
        scores['risk_level'] = 'MINIMAL'
    
    return scores

class BlockchainService:
    def __init__(self):
        self.alchemy_url = os.getenv('ALCHEMY_API_URL')
        self.infura_url = os.getenv('INFURA_API_URL')
        self.w3 = self._get_provider()
        self.cg = CoinGeckoAPI()
        self.troubleshooter = TroubleshootingUtilities()

    def _get_provider(self):
        try:
            if self.alchemy_url and 'your_key' not in self.alchemy_url.lower():
                w3 = Web3(Web3.HTTPProvider(self.alchemy_url))
                if w3.is_connected():
                    logger.info("Connected via Alchemy")
                    return w3
        except Exception as e:
            logger.warning(f"Alchemy failed: {e}. Falling back to Infura")
        
        try:
            if self.infura_url and 'your_key' not in self.infura_url.lower():
                w3 = Web3(Web3.HTTPProvider(self.infura_url))
                if w3.is_connected():
                    logger.info("Connected via Infura")
                    return w3
        except Exception as e:
            logger.warning(f"Infura failed: {e}")
        
        logger.error("No valid blockchain provider available")
        return None

    def get_transactions(self, address, num_txs=50, retry_attempts=2):
        """
        Enhanced transaction fetching with retry logic and better error handling
        """
        # Validate address first
        is_valid, issues = self.troubleshooter.validate_ethereum_address(address)
        if not is_valid:
            st.error("❌ Invalid Ethereum address")
            for issue_code, issue_msg in issues:
                st.warning(f"- {issue_msg}")
            return pd.DataFrame()
        
        # Try multiple API endpoints if needed
        api_endpoints = [
            {
                'name': 'Etherscan',
                'url': "https://api.etherscan.io/api",
                'params': {
                    'module': 'account',
                    'action': 'txlist',
                    'address': address,
                    'startblock': 0,
                    'endblock': 99999999,
                    'sort': 'desc',
                    'apikey': os.getenv('ETHERSCAN_API_KEY', 'YourApiKeyToken')
                }
            },
            {
                'name': 'Etherscan Internal',
                'url': "https://api.etherscan.io/api",
                'params': {
                    'module': 'account',
                    'action': 'txlistinternal',
                    'address': address,
                    'sort': 'desc',
                    'apikey': os.getenv('ETHERSCAN_API_KEY', 'YourApiKeyToken')
                }
            }
        ]
        
        for attempt in range(retry_attempts):
            for endpoint in api_endpoints:
                try:
                    logger.info(f"Attempt {attempt + 1}: Fetching from {endpoint['name']}")
                    response = requests.get(endpoint['url'], params=endpoint['params'], timeout=30)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        if data.get('status') == '1' and data.get('result'):
                            transactions = pd.DataFrame(data['result'][:num_txs])
                            
                            if not transactions.empty:
                                # Add additional calculated fields
                                transactions['value_eth'] = transactions['value'].astype(float) / 1e18
                                
                                if 'timeStamp' in transactions.columns:
                                    transactions['timestamp'] = transactions['timeStamp'].astype(int)
                                    transactions['datetime'] = pd.to_datetime(transactions['timestamp'], unit='s')
                                
                                # Calculate USD value if we have price data
                                try:
                                    eth_price = self.cg.get_price(ids='ethereum', vs_currencies='usd')['ethereum']['usd']
                                    transactions['value_usd'] = transactions['value_eth'] * eth_price
                                except Exception:
                                    transactions['value_usd'] = None
                                
                                st.success(f"✅ Found {len(transactions)} transactions from {endpoint['name']}")
                                return transactions
                            else:
                                logger.warning(f"No transactions in dataframe from {endpoint['name']}")
                        else:
                            error_message = data.get('message', 'Unknown API error')
                            logger.warning(f"{endpoint['name']} API error: {error_message}")
                    else:
                        logger.warning(f"{endpoint['name']} HTTP error: {response.status_code}")
                        
                except requests.exceptions.Timeout:
                    logger.error(f"{endpoint['name']} timeout on attempt {attempt + 1}")
                except Exception as e:
                    logger.error(f"Error with {endpoint['name']}: {str(e)}")
        
        # If all attempts fail, get basic address info but don't store it in an unused variable
        # Just call the method for its side effects (logging/display)
        self.get_basic_address_info(address)
        return pd.DataFrame()

    def get_basic_address_info(self, address):
        """
        Get basic information about an address even if no transactions found
        """
        info = {
            'address': address,
            'is_valid': False,
            'checksum_address': None,
            'balance_eth': 0,
            'transaction_count': 0,
            'is_contract': False,
            'error': None
        }
        
        try:
            # Get checksum address
            checksum_addr = Web3.to_checksum_address(address)
            info['checksum_address'] = checksum_addr
            info['is_valid'] = True
            
            # Get balance if provider available
            if self.w3 and self.w3.is_connected():
                balance = self.w3.eth.get_balance(checksum_addr)
                info['balance_eth'] = balance / 1e18
                
                # Get transaction count
                tx_count = self.w3.eth.get_transaction_count(checksum_addr)
                info['transaction_count'] = tx_count
                
                # Check if it's a contract
                code = self.w3.eth.get_code(checksum_addr)
                info['is_contract'] = len(code) > 2
                
        except Exception as e:
            info['error'] = str(e)
            
        return info
    
    def get_address_metadata(self, address):
        """
        Gather metadata about an address
        """
        metadata = {
            'address': address,
            'checksum_valid': Web3.is_address(address),
            'is_contract': False,
            'first_seen': None,
            'total_received': 0,
            'total_sent': 0,
            'balance_eth': 0
        }
        
        try:
            # Check if it's a contract
            code = self.w3.eth.get_code(Web3.to_checksum_address(address))
            metadata['is_contract'] = len(code) > 2  # More than 0x
            
            # Get balance
            balance = self.w3.eth.get_balance(Web3.to_checksum_address(address))
            metadata['balance_eth'] = balance / 1e18
            
            # Get transaction count (nonce)
            nonce = self.w3.eth.get_transaction_count(Web3.to_checksum_address(address))
            metadata['transaction_count'] = nonce
            
        except Exception as e:
            logger.error(f"Error getting metadata for {address}: {e}")
        
        return metadata

class ForensicScanner:
    """
    Main forensic scanner integrating all detection methods
    """
    
    def __init__(self):
        self.heuristics = ForensicHeuristics()
        self.known_suspicious_patterns = self._load_suspicious_patterns()
    
    def _load_suspicious_patterns(self):
        """
        Load patterns of known suspicious activities
        """
        return {
            'peeling_chain': {'threshold': 3, 'risk_weight': 1.5},
            'rapid_movement': {'threshold': 3, 'risk_weight': 1.3},
            'mixer_interaction': {'threshold': 1, 'risk_weight': 2.0},
            'round_trip': {'threshold': 1, 'risk_weight': 1.4}
        }
    
    def scan_address(self, address, transactions):
        """
        Comprehensive scan of an address and its transactions
        """
        if transactions.empty:
            return {
                'status': 'NO_DATA',
                'findings': [],
                'risk_summary': {
                    'overall_risk': 0,
                    'risk_level': 'MINIMAL',
                    'alerts': 0
                }
            }
        
        findings = []
        
        # 1. Check for mixer interactions
        mixer_findings = self.heuristics.detect_mixer_interaction(address, transactions)
        findings.extend(mixer_findings)
        
        # 2. Detect peeling chain patterns
        peeling_findings = self.heuristics.detect_peeling_chain(transactions)
        findings.extend(peeling_findings)
        
        # 3. Detect rapid movement
        rapid_findings = self.heuristics.detect_rapid_movement(transactions)
        findings.extend(rapid_findings)
        
        # 4. Detect round trips
        roundtrip_findings = self.heuristics.detect_round_trip(transactions, address)
        findings.extend(roundtrip_findings)
        
        # 5. Detect potential coinjoin
        coinjoin_findings = self.heuristics.detect_coinjoin_pattern(transactions)
        findings.extend(coinjoin_findings)
        
        # Calculate overall risk
        if findings:
            max_risk = max(f.get('risk_score', 0) for f in findings)
            avg_risk = np.mean([f.get('risk_score', 0) for f in findings])
            risk_score = min(100, (max_risk * 0.6 + avg_risk * 0.4))
        else:
            risk_score = 0
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        elif risk_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'status': 'COMPLETE',
            'findings': findings,
            'risk_summary': {
                'overall_risk': float(risk_score),
                'risk_level': risk_level,
                'alerts': len(findings),
                'critical_alerts': len([f for f in findings if f.get('risk_score', 0) >= 80]),
                'high_alerts': len([f for f in findings if 60 <= f.get('risk_score', 0) < 80])
            },
            'transaction_summary': {
                'total_transactions': len(transactions),
                'unique_counterparties': transactions['to'].nunique() + transactions['from'].nunique() - 1,
                'total_volume_eth': float(transactions['value_eth'].sum() if 'value_eth' in transactions.columns else 0),
                'time_range_days': None
            }
        }
    
    def generate_sar_report(self, address, scan_results, transactions):
        """
        Generate Suspicious Activity Report
        """
        import hashlib
        
        report = {
            'report_id': f"SAR-{hashlib.md5(address.encode()).hexdigest()[:8]}-{int(datetime.now().timestamp())}",
            'generated_date': datetime.now().isoformat(),
            'subject_address': address,
            'executive_summary': '',
            'detailed_findings': scan_results['findings'],
            'risk_assessment': scan_results['risk_summary'],
            'recommended_actions': [],
            'investigator_notes': ''
        }
        
        # Generate executive summary based on findings
        if scan_results['risk_summary']['critical_alerts'] > 0:
            report['executive_summary'] = (
                f"CRITICAL ALERT: Address exhibits multiple high-risk patterns including "
                f"{scan_results['risk_summary']['critical_alerts']} critical findings. "
                f"Immediate investigation recommended."
            )
            report['recommended_actions'] = [
                "Freeze associated accounts",
                "File SAR with FinCEN",
                "Conduct enhanced due diligence",
                "Monitor for future activity"
            ]
        elif scan_results['risk_summary']['high_alerts'] > 0:
            report['executive_summary'] = (
                f"HIGH RISK: Address shows {scan_results['risk_summary']['alerts']} suspicious patterns. "
                f"Enhanced monitoring required."
            )
            report['recommended_actions'] = [
                "Conduct enhanced due diligence",
                "Monitor for 90 days",
                "Review transaction history quarterly"
            ]
        else:
            report['executive_summary'] = (
                    "LOW RISK: Address shows minimal suspicious activity. "
                    "Routine monitoring recommended."
            )
            report['recommended_actions'] = [
                "Routine quarterly review",
                "Standard monitoring procedures"
            ]
        
        return report

def ai_analyze(transactions_df, risk_data, scan_results):
    """
    Enhanced AI analysis with forensic context
    """
    analysis_template = """
    ## Forensic Investigation Summary
    
    **Address Risk Level:** {risk_level}
    **Overall Risk Score:** {overall_risk:.1f}/100
    **Suspicious Pattern Alerts:** {alerts}
    
    ### Key Findings:
    """.format(
        risk_level=scan_results['risk_summary']['risk_level'],
        overall_risk=scan_results['risk_summary']['overall_risk'],
        alerts=scan_results['risk_summary']['alerts']
    )
    
    for i, finding in enumerate(scan_results['findings'][:5], 1):
        analysis_template += f"\n{i}. **{finding.get('pattern', finding.get('type', 'Unknown'))}** - Risk: {finding.get('risk_score', 0)}/100"
        if 'description' in finding:
            analysis_template += f"\n   {finding['description']}"
    
    analysis_template += """
    
    ### Investigative Assessment:
    """
    
    if scan_results['risk_summary']['risk_level'] in ['CRITICAL', 'HIGH']:
        analysis_template += """
    **Assessment:** Address exhibits multiple characteristics consistent with money laundering or other illicit financial activity.
    **Recommendation:** Immediate enhanced due diligence and consideration of SAR filing.
    
    ### Indicators of Concern:
    1. Transaction patterns suggest structuring or layering
    2. Connections to high-risk counterparties
    3. Unusual velocity of funds movement
    """
    else:
        analysis_template += """
    **Assessment:** Address shows limited signs of suspicious activity.
    **Recommendation:** Continue standard monitoring procedures.
    """
    
    analysis_template += f"""
    
    ### Technical Notes:
    - Analysis based on {len(transactions_df)} transactions
    - Forensic rubric score incorporates network analysis, pattern recognition, and behavioral heuristics
    - {len(scan_results['findings'])} heuristic triggers identified
    
    **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """
    
    return analysis_template

# Dashboard UI
st.set_page_config(
    page_title="CryptoTrace Forensic Analyzer",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 CryptoTrace Forensic Analyzer")
st.markdown("### Advanced Blockchain Forensics & Risk Assessment Platform")

# Initialize troubleshooting utilities
troubleshooter = TroubleshootingUtilities()

# Sidebar configuration
with st.sidebar:
    st.header("Configuration")
    
    # API Status Check
    with st.expander("🔧 API Status Check", expanded=False):
        if st.button("Check API Status"):
            with st.spinner("Checking API status..."):
                api_status = troubleshooter.check_api_status()
                
                for api_name, status_info in api_status.items():
                    if status_info['status'] == 'OK':
                        st.success(f"✅ {api_name}: Operational")
                    else:
                        st.error(f"❌ {api_name}: Error")
                        if 'error' in status_info:
                            st.warning(f"Error: {status_info['error']}")
    
    # Address input
    address = st.text_input("Enter Wallet Address:", 
                          placeholder="0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
    
    # Validate address on input
    if address:
        is_valid, issues = troubleshooter.validate_ethereum_address(address)
        if not is_valid:
            st.error("❌ Invalid address format")
            for issue_code, issue_msg in issues:
                st.warning(f"⚠️ {issue_msg}")
        else:
            st.success("✅ Valid Ethereum address")
    
    # Known bad addresses
    known_bad_input = st.text_area(
        "Known Suspicious Addresses (comma-separated):",
        placeholder="0xbad1,0xbad2,0xbad3",
        help="Enter addresses known to be associated with illicit activity"
    )
    
    known_bad = [addr.strip() for addr in known_bad_input.split(",") if addr.strip()]
    
    # Analysis options
    st.subheader("Analysis Options")
    num_transactions = st.slider("Number of transactions to analyze:", 10, 200, 50)
    enable_ai = st.checkbox("Enable AI Analysis", value=True)
    generate_report = st.checkbox("Generate SAR Report", value=True)
    
    # Example addresses for testing
    with st.expander("📋 Example Addresses", expanded=False):
        st.write("**Active Addresses (with transactions):**")
        st.code("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        st.code("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae")
        
        st.write("**Test/Zero Addresses:**")
        st.code("0x0000000000000000000000000000000000000000")
        
        st.write("**Exchange Addresses:**")
        st.code("0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE")

# Main analysis area
if address:
    # Create tabs for different functionalities
    analysis_tab, troubleshoot_tab = st.tabs(["🚨 Launch Investigation", "🔧 Troubleshooting"])
    
    with analysis_tab:
        if st.button("🚨 Launch Forensic Investigation", type="primary", use_container_width=True):
            with st.spinner("🔍 Initializing forensic scan..."):
                # Initialize services
                bs = BlockchainService()
                scanner = ForensicScanner()
                
                # Create progress tracker
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Step 1: Validate address
                status_text.text("🔍 Validating address...")
                is_valid, issues = troubleshooter.validate_ethereum_address(address)
                if not is_valid:
                    st.error("❌ Address validation failed")
                    for issue_code, issue_msg in issues:
                        st.warning(f"- {issue_msg}")
                    st.stop()
                
                progress_bar.progress(10)
                
                # Step 2: Fetch transactions
                status_text.text("📡 Fetching transaction history...")
                txs = bs.get_transactions(address, num_transactions)
                
                if txs.empty:
                    # Show troubleshooting information
                    st.error("❌ No transactions found for this address.")
                    
                    # Get basic address info
                    address_info = bs.get_basic_address_info(address)
                    
                    # Display troubleshooting panel
                    with st.expander("🔍 Troubleshooting Information", expanded=True):
                        st.subheader("Address Analysis")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Address Valid", "✅" if address_info['is_valid'] else "❌")
                        with col2:
                            if address_info['is_valid']:
                                st.metric("Balance (ETH)", f"{address_info['balance_eth']:.4f}")
                        
                        # Show suggestions
                        st.subheader("Possible Reasons & Solutions")
                        
                        suggestions = troubleshooter.suggest_common_issues(address)
                        if suggestions:
                            for suggestion in suggestions:
                                st.info(f"💡 {suggestion}")
                        
                        # Common issues checklist
                        st.subheader("Checklist")
                        
                        issues_to_check = [
                            ("✅ Address format is valid", address_info['is_valid']),
                            ("✅ Connected to Ethereum mainnet", bs.w3 and bs.w3.is_connected()),
                            ("📊 Address has balance", address_info['balance_eth'] > 0),
                            ("🔄 Address has transaction history", address_info['transaction_count'] > 0),
                            ("⚙️ Address is a smart contract", address_info['is_contract'])
                        ]
                        
                        for check_text, check_status in issues_to_check:
                            if check_status:
                                st.success(check_text)
                            else:
                                st.warning(check_text)
                        
                        # Specific recommendations based on findings
                        st.subheader("Recommendations")
                        
                        if address_info['transaction_count'] == 0 and address_info['balance_eth'] == 0:
                            st.info("""
                            **This appears to be a new/unused address.**
                            1. Check if the address was created recently
                            2. Verify you're analyzing the correct network (Ethereum Mainnet)
                            3. Consider that this might be a test address
                            """)
                        
                        elif address_info['is_contract']:
                            st.info("""
                            **This is a smart contract address.**
                            1. Contract addresses have different transaction patterns
                            2. Try analyzing internal transactions separately
                            3. Consider using contract-specific analysis tools
                            """)
                        
                        # Provide alternative actions
                        st.subheader("Next Steps")
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("🔄 Try Internal Transactions"):
                                st.info("Some addresses only have internal transactions. Try the internal transaction scan.")
                        with col2:
                            if st.button("📋 View Raw Address Info"):
                                st.json(address_info)
                    
                    # Don't proceed with analysis
                    st.stop()
                
                progress_bar.progress(25)
                
                # Step 2: Perform forensic scan
                status_text.text("🔬 Performing forensic analysis...")
                scan_results = scanner.scan_address(address, txs)
                progress_bar.progress(50)
                
                # Step 3: Build transaction graph
                status_text.text("📊 Building transaction network...")
                G = nx.DiGraph()
                tx_values = []
                
                for _, tx in txs.iterrows():
                    G.add_edge(tx['from'], tx['to'], 
                              value=float(tx['value']),
                              timestamp=tx['timestamp'] if 'timestamp' in tx else None)
                    tx_values.append(float(tx['value']))
                
                # Get address metadata
                metadata = bs.get_address_metadata(address)
                
                # Step 4: Calculate forensic rubric
                status_text.text("📈 Calculating risk scores...")
                rubric_scores = forensic_rubric(G, known_bad, tx_values, metadata)
                progress_bar.progress(75)
                
                # Step 5: AI Analysis (if enabled)
                if enable_ai:
                    status_text.text("🤖 Generating AI analysis...")
                    analysis = ai_analyze(txs, rubric_scores, scan_results)
                
                progress_bar.progress(100)
                status_text.text("✅ Analysis complete!")
                
                # Display results in tabs
                tab1, tab2, tab3, tab4, tab5 = st.tabs([
                    "📋 Overview", 
                    "📊 Risk Assessment", 
                    "🔍 Forensic Findings",
                    "🕸️ Network Graph",
                    "📄 SAR Report"
                ])
                
                with tab1:
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric(
                            "Overall Risk Score",
                            f"{rubric_scores['overall_risk']:.1f}/100",
                            delta=None,
                            delta_color="inverse"
                        )
                    
                    with col2:
                        risk_level = rubric_scores.get('risk_level', 'UNKNOWN')
                        risk_color = {
                            'CRITICAL': 'red',
                            'HIGH': 'orange',
                            'MEDIUM': 'yellow',
                            'LOW': 'green',
                            'MINIMAL': 'blue'
                        }.get(risk_level, 'gray')
                        
                        st.markdown(f"""
                        <div style="padding: 10px; border-radius: 5px; background-color: {risk_color}20; border-left: 5px solid {risk_color};">
                            <h4 style="margin: 0; color: {risk_color};">Risk Level: {risk_level}</h4>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col3:
                        st.metric(
                            "Suspicious Patterns",
                            scan_results['risk_summary']['alerts'],
                            delta=f"{scan_results['risk_summary']['critical_alerts']} critical"
                        )
                    
                    # Transaction summary
                    st.subheader("Transaction Summary")
                    st.dataframe(txs[['hash', 'from', 'to', 'value_eth', 'datetime']].head(20) 
                                if 'datetime' in txs.columns 
                                else txs[['hash', 'from', 'to', 'value_eth']].head(20))
                
                with tab2:
                    st.subheader("Detailed Risk Assessment")
                    
                    # Display rubric scores
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write("### Risk Dimensions")
                        for dim_name, dim_data in rubric_scores.get('dimensions', {}).items():
                            if isinstance(dim_data, dict) and 'score' in dim_data:
                                st.progress(dim_data['score']/100, 
                                          text=f"{dim_name.replace('_', ' ').title()}: {dim_data['score']:.1f}")
                    
                    with col2:
                        st.write("### Risk Breakdown")
                        risk_data = {
                            'Network Analysis': rubric_scores['dimensions'].get('centrality_risk', {}).get('score', 0),
                            'Bad Address Proximity': rubric_scores['dimensions'].get('bad_proximity', {}).get('score', 0),
                            'Transaction Patterns': rubric_scores['dimensions'].get('volume_analysis', {}).get('score', 0),
                            'Clustering Behavior': rubric_scores['dimensions'].get('clustering', {}).get('score', 0)
                        }
                        
                        chart_data = pd.DataFrame({
                            'Dimension': list(risk_data.keys()),
                            'Score': list(risk_data.values())
                        })
                        
                        st.bar_chart(chart_data.set_index('Dimension'))
                
                with tab3:
                    st.subheader("🔍 Forensic Findings")
                    
                    if scan_results['findings']:
                        for i, finding in enumerate(scan_results['findings'], 1):
                            with st.expander(f"Finding #{i}: {finding.get('pattern', finding.get('type', 'Unknown'))} - Risk: {finding.get('risk_score', 0)}"):
                                st.json(finding, expanded=False)
                    else:
                        st.success("✅ No suspicious patterns detected in this scan.")
                
                with tab4:
                    st.subheader("Transaction Network Graph")
                    
                    if G.number_of_nodes() > 0:
                        # Create interactive network
                        net = Network(
                            height="600px", 
                            width="100%",
                            directed=True,
                            notebook=False,
                            cdn_resources='remote'
                        )
                        
                        # Add nodes with styling
                        for node in G.nodes():
                            if node == address:
                                # Highlight target address
                                net.add_node(node, label=node[:10]+"...", 
                                           color='red', size=30, 
                                           title=f"Target: {node}")
                            elif node in known_bad:
                                # Highlight known bad addresses
                                net.add_node(node, label=node[:8]+"...", 
                                           color='orange', size=20,
                                           title=f"Known suspicious: {node}")
                            else:
                                net.add_node(node, label=node[:6]+"...", 
                                           color='blue', size=10,
                                           title=node)
                        
                        # Add edges with weights
                        for edge in G.edges(data=True):
                            value = edge[2].get('value', 0)
                            # Scale edge width by transaction value
                            width = max(1, min(10, np.log10(value + 1)))
                            net.add_edge(edge[0], edge[1], 
                                       value=width,
                                       title=f"Value: {value:.2f} wei")
                        
                        # Save and display
                        net.save_graph("tx_graph.html")
                        st.components.v1.html(open("tx_graph.html").read(), 
                                            height=620)
                    else:
                        st.warning("No network data to display.")
                
                with tab5:
                    st.subheader("📄 Suspicious Activity Report")
                    
                    if generate_report:
                        sar_report = scanner.generate_sar_report(address, scan_results, txs)
                        
                        # Display report
                        st.markdown(f"""
                        ### SAR Report: {sar_report['report_id']}
                        **Generated:** {sar_report['generated_date']}
                        **Subject:** {sar_report['subject_address']}
                        
                        #### Executive Summary
                        {sar_report['executive_summary']}
                        
                        #### Risk Assessment
                        - Overall Risk: {sar_report['risk_assessment']['overall_risk']:.1f}/100
                        - Risk Level: {sar_report['risk_assessment']['risk_level']}
                        - Total Alerts: {sar_report['risk_assessment']['alerts']}
                        - Critical Alerts: {sar_report['risk_assessment']['critical_alerts']}
                        """)
                        
                        # Download button for report
                        report_json = json.dumps(sar_report, indent=2)
                        st.download_button(
                            label="📥 Download SAR Report (JSON)",
                            data=report_json,
                            file_name=f"sar_report_{address[:10]}_{datetime.now().strftime('%Y%m%d')}.json",
                            mime="application/json"
                        )
                
                # AI Analysis section (if enabled)
                if enable_ai:
                    st.divider()
                    st.subheader("🤖 AI Investigative Summary")
                    st.markdown(analysis)
            
            # Cleanup
            try:
                os.remove("tx_graph.html")
            except OSError:
                pass
    
    with troubleshoot_tab:
        st.header("🔧 Troubleshooting Center")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Common Issues")
            
            issues = [
                ("❌ No transactions found", "Address may be new, a contract, or on wrong network"),
                ("⚠️ Invalid address format", "Check for 0x prefix and 40 hex characters"),
                ("🔗 API connection failed", "Check API keys and internet connection"),
                ("📊 Empty transaction list", "Address may have only internal transactions"),
                ("🌐 Wrong blockchain network", "Ensure you're analyzing Ethereum Mainnet")
            ]
            
            for icon, description in issues:
                st.write(f"{icon} {description}")
        
        with col2:
            st.subheader("Quick Diagnostics")
            
            if st.button("Run Diagnostic Check"):
                with st.spinner("Running diagnostics..."):
                    # Check API status
                    api_status = troubleshooter.check_api_status()
                    
                    # Validate current address if provided
                    if address:
                        is_valid, issues = troubleshooter.validate_ethereum_address(address)
                        
                        st.subheader("Diagnostic Results")
                        
                        # API Status
                        st.write("**API Status:**")
                        for api_name, status_info in api_status.items():
                            status_icon = "✅" if status_info['status'] == 'OK' else "❌"
                            st.write(f"{status_icon} {api_name}: {status_info['status']}")
                        
                        # Address Validation
                        st.write("**Address Validation:**")
                        if is_valid:
                            st.success("✅ Address format is valid")
                        else:
                            st.error("❌ Address format is invalid")
                            for issue_code, issue_msg in issues:
                                st.warning(f"- {issue_msg}")
        
        st.subheader("Troubleshooting Steps")
        
        with st.expander("1. Address Validation Issues", expanded=False):
            st.markdown("""
            ### Common Address Problems:
            
            **Invalid Format:**
            - Must start with `0x`
            - Must be exactly 42 characters (`0x` + 40 hex chars)
            - Only contains characters 0-9, a-f, A-F
            
            **Checksum Issues:**
            - Ethereum addresses use EIP-55 checksum
            - Mixed case indicates checksum validation
            - Try using: `Web3.to_checksum_address(your_address)`
            
            **Test Addresses:**
            - `0x0000000000000000000000000000000000000000` - Zero address
            - `0x1111111111111111111111111111111111111111` - Test pattern
            """)
        
        with st.expander("2. Transaction Retrieval Issues", expanded=False):
            st.markdown("""
            ### Why No Transactions Found:
            
            **New/Unused Address:**
            - Address was recently created
            - Has never sent or received ETH
            - Check balance: `0 ETH` means likely unused
            
            **Contract Address:**
            - Smart contracts behave differently
            - May have only internal transactions
            - Use `getCode` to check if contract
            
            **Network Issues:**
            - Wrong network (Ethereum vs Testnet)
            - API rate limiting
            - Internet connectivity problems
            
            **Exchange Addresses:**
            - Large exchanges use complex internal systems
            - Transactions may be batched internally
            - Need specialized exchange analysis
            """)
        
        with st.expander("3. API Configuration", expanded=False):
            st.markdown("""
            ### API Configuration Check:
            
            **Required API Keys:**
            ```env
            ETHERSCAN_API_KEY=YourApiKeyToken
            ALCHEMY_API_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
            INFURA_API_URL=https://mainnet.infura.io/v3/YOUR_KEY
            ```
            
            **Testing API Connectivity:**
            - Etherscan: Visit https://api.etherscan.io
            - Check API key usage on Etherscan dashboard
            - Verify network connectivity
            
            **Rate Limiting:**
            - Free tier: 5 calls/sec, 100,000 calls/day
            - Paid tiers available for higher limits
            - Implement retry logic for rate limits
            """)
        
        with st.expander("4. Alternative Solutions", expanded=False):
            st.markdown("""
            ### When Standard Methods Fail:
            
            **Try Internal Transactions:**
            - Some addresses only have internal transactions
            - Use `txlistinternal` API endpoint
            - Common for contract interactions
            
            **Check Different Networks:**
            - Test on Ethereum Testnets (Goerli, Sepolia)
            - Check if address exists on other chains
            - Verify you're analyzing the correct chain
            
            **Manual Verification:**
            - Use Etherscan.io directly
            - Check blockchain explorers
            - Verify address on multiple sources
            
            **Alternative Data Sources:**
            - Alchemy Enhanced APIs
            - Infura Transaction endpoints
            - Moralis blockchain APIs
            """)

else:
    # Welcome screen
    st.info("👈 Enter a wallet address in the sidebar to begin forensic analysis.")
    
    # Example analysis
    st.subheader("Example Suspicious Patterns Detected:")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        ### 🌀 Mixer Interaction
        **Detection:** Transactions to/from known mixing services
        **Risk:** High (80-100)
        **Indicators:** 
        - Direct transfers to mixer addresses
        - Funds received from anonymous pools
        """)
    
    with col2:
        st.markdown("""
        ### 🔄 Peeling Chain
        **Detection:** Structured transfers through multiple addresses
        **Risk:** Medium-High (60-80)
        **Indicators:**
        - Same amount sent to multiple addresses
        - Sequential transactions
        """)
    
    with col3:
        st.markdown("""
        ### ⚡ Rapid Movement
        **Detection:** High-frequency transactions
        **Risk:** Medium (40-60)
        **Indicators:**
        - Multiple transactions in short timeframe
        - Unusual velocity of funds
        """)
    
    # Technology stack
    st.divider()
    st.subheader("🛠️ Forensic Technology Stack")
    
    tech_cols = st.columns(4)
    technologies = [
        ("Web3.py", "Blockchain interaction & data retrieval"),
        ("NetworkX", "Graph analysis & pattern recognition"),
        ("PyVis", "Interactive network visualization"),
        ("Forensic Heuristics", "Custom detection algorithms")
    ]
    
    for idx, (name, desc) in enumerate(technologies):
        with tech_cols[idx]:
            st.metric(name, desc, delta_color="off")
    
    # Troubleshooting section on welcome page
    st.divider()
    st.subheader("🔧 Common Issues & Solutions")
    
    troubleshooting_cols = st.columns(2)
    
    with troubleshooting_cols[0]:
        st.markdown("""
        ### ❌ No Transactions Found?
        
        **Possible Causes:**
        1. **Invalid address format** - Check for 0x prefix
        2. **New/unused address** - Check balance and creation date
        3. **Contract address** - Use contract-specific analysis
        4. **API issues** - Verify API keys and connectivity
        
        **Solutions:**
        - Use the Troubleshooting tab
        - Try example addresses first
        - Check API status
        - Verify address on Etherscan
        """)
    
    with troubleshooting_cols[1]:
        st.markdown("""
        ### ⚠️ Error Messages?
        
        **Common Errors:**
        - "Invalid API Key" - Update .env file
        - "Rate limited" - Wait or upgrade API tier
        - "Network error" - Check internet connection
        - "Invalid response" - API may be temporarily down
        
        **Quick Fixes:**
        1. Restart the application
        2. Check .env configuration
        3. Try alternative addresses
        4. Use the diagnostic tools
        """)

# Footer
st.divider()
st.caption("""
🔒 **CryptoTrace Forensic Analyzer** v1.1 | 
For Law Enforcement & Financial Institution Use Only | 
All analysis should be verified through official channels
""")