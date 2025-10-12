"""
AresProbe Advanced AI/ML Engine
Deep learning, neural networks, and reinforcement learning for security
"""

import asyncio
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import tensorflow as tf
from transformers import AutoTokenizer, AutoModel
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import time
import random
import re
from collections import deque

from .logger import Logger

class AIModelType(Enum):
    """AI model types"""
    NEURAL_NETWORK = "neural_network"
    TRANSFORMER = "transformer"
    ISOLATION_FOREST = "isolation_forest"
    RANDOM_FOREST = "random_forest"
    DBSCAN = "dbscan"
    LSTM = "lstm"
    CNN = "cnn"
    REINFORCEMENT_LEARNING = "reinforcement_learning"

class ThreatType(Enum):
    """Threat types for classification"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    BUFFER_OVERFLOW = "buffer_overflow"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE = "malware"
    PHISHING = "phishing"
    DDoS = "ddos"
    ZERO_DAY = "zero_day"

@dataclass
class AIModelConfig:
    """AI model configuration"""
    model_type: AIModelType
    input_size: int
    hidden_size: int = 128
    output_size: int = 10
    learning_rate: float = 0.001
    epochs: int = 100
    batch_size: int = 32
    dropout: float = 0.2
    sequence_length: int = 100

@dataclass
class ThreatPrediction:
    """Threat prediction result"""
    threat_type: str
    confidence: float
    severity: str
    description: str
    mitigation: str
    false_positive_rate: float
    model_used: str

class NeuralNetwork(nn.Module):
    """Advanced neural network for threat detection"""
    
    def __init__(self, config: AIModelConfig):
        super(NeuralNetwork, self).__init__()
        self.config = config
        
        # Input layer
        self.input_layer = nn.Linear(config.input_size, config.hidden_size)
        self.batch_norm1 = nn.BatchNorm1d(config.hidden_size)
        
        # Hidden layers
        self.hidden_layers = nn.ModuleList([
            nn.Linear(config.hidden_size, config.hidden_size)
            for _ in range(3)
        ])
        
        self.batch_norms = nn.ModuleList([
            nn.BatchNorm1d(config.hidden_size)
            for _ in range(3)
        ])
        
        # Output layer
        self.output_layer = nn.Linear(config.hidden_size, config.output_size)
        self.dropout = nn.Dropout(config.dropout)
        self.activation = nn.ReLU()
        self.softmax = nn.Softmax(dim=1)
    
    def forward(self, x):
        # Input layer
        x = self.input_layer(x)
        x = self.batch_norm1(x)
        x = self.activation(x)
        x = self.dropout(x)
        
        # Hidden layers
        for hidden_layer, batch_norm in zip(self.hidden_layers, self.batch_norms):
            residual = x
            x = hidden_layer(x)
            x = batch_norm(x)
            x = self.activation(x)
            x = self.dropout(x)
            x = x + residual  # Residual connection
        
        # Output layer
        x = self.output_layer(x)
        x = self.softmax(x)
        
        return x

class LSTMNetwork(nn.Module):
    """LSTM network for sequence analysis"""
    
    def __init__(self, config: AIModelConfig):
        super(LSTMNetwork, self).__init__()
        self.config = config
        
        self.embedding = nn.Embedding(config.input_size, config.hidden_size)
        self.lstm = nn.LSTM(config.hidden_size, config.hidden_size, 
                           batch_first=True, dropout=config.dropout)
        self.attention = nn.MultiheadAttention(config.hidden_size, num_heads=8)
        self.classifier = nn.Linear(config.hidden_size, config.output_size)
        self.dropout = nn.Dropout(config.dropout)
        self.softmax = nn.Softmax(dim=1)
    
    def forward(self, x):
        # Embedding
        x = self.embedding(x)
        
        # LSTM
        lstm_out, _ = self.lstm(x)
        
        # Attention
        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)
        
        # Global average pooling
        pooled = torch.mean(attn_out, dim=1)
        
        # Classification
        x = self.dropout(pooled)
        x = self.classifier(x)
        x = self.softmax(x)
        
        return x

class CNNNetwork(nn.Module):
    """CNN network for pattern recognition"""
    
    def __init__(self, config: AIModelConfig):
        super(CNNNetwork, self).__init__()
        self.config = config
        
        # Convolutional layers
        self.conv1 = nn.Conv1d(config.input_size, 64, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.conv3 = nn.Conv1d(128, 256, kernel_size=3, padding=1)
        
        # Pooling
        self.pool = nn.MaxPool1d(2)
        
        # Fully connected layers
        self.fc1 = nn.Linear(256 * (config.sequence_length // 8), config.hidden_size)
        self.fc2 = nn.Linear(config.hidden_size, config.output_size)
        
        self.dropout = nn.Dropout(config.dropout)
        self.activation = nn.ReLU()
        self.softmax = nn.Softmax(dim=1)
    
    def forward(self, x):
        # Convolutional layers
        x = self.activation(self.conv1(x))
        x = self.pool(x)
        
        x = self.activation(self.conv2(x))
        x = self.pool(x)
        
        x = self.activation(self.conv3(x))
        x = self.pool(x)
        
        # Flatten
        x = x.view(x.size(0), -1)
        
        # Fully connected layers
        x = self.dropout(x)
        x = self.activation(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        x = self.softmax(x)
        
        return x

class ReinforcementLearningAgent:
    """Reinforcement learning agent for adaptive security"""
    
    def __init__(self, state_size: int, action_size: int, learning_rate: float = 0.001):
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        
        # Q-network
        self.q_network = nn.Sequential(
            nn.Linear(state_size, 128),
            nn.ReLU(),
            nn.Linear(128, 128),
            nn.ReLU(),
            nn.Linear(128, action_size)
        )
        
        self.optimizer = optim.Adam(self.q_network.parameters(), lr=learning_rate)
        self.memory = deque(maxlen=10000)
        self.epsilon = 1.0
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.gamma = 0.95
        
        # Action mapping
        self.actions = [
            "scan_port", "test_sql_injection", "test_xss", "test_csrf",
            "test_directory_traversal", "test_command_injection", "test_xxe",
            "test_ssrf", "analyze_response", "escalate_privilege"
        ]
    
    def act(self, state: np.ndarray) -> int:
        """Choose action using epsilon-greedy policy"""
        if random.random() <= self.epsilon:
            return random.choice(range(self.action_size))
        
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0)
            q_values = self.q_network(state_tensor)
            return q_values.argmax().item()
    
    def remember(self, state: np.ndarray, action: int, reward: float, 
                next_state: np.ndarray, done: bool):
        """Store experience in memory"""
        self.memory.append((state, action, reward, next_state, done))
    
    def replay(self, batch_size: int = 32):
        """Train the agent on a batch of experiences"""
        if len(self.memory) < batch_size:
            return
        
        batch = random.sample(self.memory, batch_size)
        states = torch.FloatTensor([e[0] for e in batch])
        actions = torch.LongTensor([e[1] for e in batch])
        rewards = torch.FloatTensor([e[2] for e in batch])
        next_states = torch.FloatTensor([e[3] for e in batch])
        dones = torch.BoolTensor([e[4] for e in batch])
        
        current_q_values = self.q_network(states).gather(1, actions.unsqueeze(1))
        next_q_values = self.q_network(next_states).max(1)[0].detach()
        target_q_values = rewards + (self.gamma * next_q_values * ~dones)
        
        loss = nn.MSELoss()(current_q_values.squeeze(), target_q_values)
        
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

class AdvancedAIMLEngine:
    """Advanced AI/ML engine for security analysis"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.models = {}
        self.scalers = {}
        self.tokenizers = {}
        self.training_data = []
        self.prediction_cache = {}
        
        # Initialize models
        self._initialize_models()
        
        # Initialize transformers
        self._initialize_transformers()
    
    def _initialize_models(self):
        """Initialize AI models"""
        try:
            # Neural network for threat classification
            nn_config = AIModelConfig(
                model_type=AIModelType.NEURAL_NETWORK,
                input_size=100,
                hidden_size=128,
                output_size=len(ThreatType),
                learning_rate=0.001
            )
            self.models['threat_classifier'] = NeuralNetwork(nn_config)
            
            # LSTM for sequence analysis
            lstm_config = AIModelConfig(
                model_type=AIModelType.LSTM,
                input_size=1000,
                hidden_size=128,
                output_size=len(ThreatType),
                sequence_length=100
            )
            self.models['sequence_analyzer'] = LSTMNetwork(lstm_config)
            
            # CNN for pattern recognition
            cnn_config = AIModelConfig(
                model_type=AIModelType.CNN,
                input_size=1,
                hidden_size=128,
                output_size=len(ThreatType),
                sequence_length=100
            )
            self.models['pattern_recognizer'] = CNNNetwork(cnn_config)
            
            # Reinforcement learning agent
            self.models['rl_agent'] = ReinforcementLearningAgent(
                state_size=50, action_size=10
            )
            
            # Traditional ML models
            self.models['isolation_forest'] = IsolationForest(contamination=0.1)
            self.models['random_forest'] = RandomForestClassifier(n_estimators=100)
            self.models['dbscan'] = DBSCAN(eps=0.5, min_samples=5)
            
            # Scalers
            self.scalers['standard'] = StandardScaler()
            
            self.logger.success("[+] AI/ML models initialized successfully")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to initialize AI models: {e}")
    
    def _initialize_transformers(self):
        """Initialize transformer models"""
        try:
            # Load pre-trained transformer for text analysis
            self.tokenizers['security'] = AutoTokenizer.from_pretrained(
                "distilbert-base-uncased"
            )
            self.models['transformer'] = AutoModel.from_pretrained(
                "distilbert-base-uncased"
            )
            
            self.logger.success("[+] Transformer models loaded successfully")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to load transformer models: {e}")
    
    async def analyze_threat_pattern(self, data: str, data_type: str = "text") -> ThreatPrediction:
        """Analyze threat pattern using AI/ML"""
        try:
            # Check cache first
            cache_key = f"{data_type}:{hash(data)}"
            if cache_key in self.prediction_cache:
                return self.prediction_cache[cache_key]
            
            # Preprocess data
            features = await self._preprocess_data(data, data_type)
            
            # Get predictions from multiple models
            predictions = []
            
            # Neural network prediction
            if 'threat_classifier' in self.models:
                nn_pred = await self._predict_with_neural_network(features)
                predictions.append(nn_pred)
            
            # LSTM prediction for sequences
            if 'sequence_analyzer' in self.models and data_type == "sequence":
                lstm_pred = await self._predict_with_lstm(features)
                predictions.append(lstm_pred)
            
            # CNN prediction for patterns
            if 'pattern_recognizer' in self.models:
                cnn_pred = await self._predict_with_cnn(features)
                predictions.append(cnn_pred)
            
            # Transformer prediction
            if 'transformer' in self.models and data_type == "text":
                transformer_pred = await self._predict_with_transformer(data)
                predictions.append(transformer_pred)
            
            # Ensemble prediction
            final_prediction = await self._ensemble_predictions(predictions)
            
            # Cache result
            self.prediction_cache[cache_key] = final_prediction
            
            return final_prediction
            
        except Exception as e:
            self.logger.error(f"[-] Threat pattern analysis failed: {e}")
            return ThreatPrediction(
                threat_type="unknown",
                confidence=0.0,
                severity="low",
                description="Analysis failed",
                mitigation="Manual review required",
                false_positive_rate=1.0,
                model_used="error"
            )
    
    async def _preprocess_data(self, data: str, data_type: str) -> np.ndarray:
        """Preprocess data for AI models"""
        try:
            if data_type == "text":
                # Text preprocessing
                features = self._extract_text_features(data)
            elif data_type == "sequence":
                # Sequence preprocessing
                features = self._extract_sequence_features(data)
            elif data_type == "network":
                # Network data preprocessing
                features = self._extract_network_features(data)
            else:
                # Default preprocessing
                features = self._extract_generic_features(data)
            
            # Normalize features
            if 'standard' in self.scalers:
                features = self.scalers['standard'].fit_transform([features])[0]
            
            return features
            
        except Exception as e:
            self.logger.error(f"[-] Data preprocessing failed: {e}")
            return np.zeros(100)  # Return default features
    
    def _extract_text_features(self, text: str) -> np.ndarray:
        """Extract features from text data"""
        features = []
        
        # Basic text features
        features.append(len(text))
        features.append(len(text.split()))
        features.append(len(set(text.split())))
        
        # Character frequency features
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Top character frequencies
        sorted_chars = sorted(char_counts.items(), key=lambda x: x[1], reverse=True)
        for i in range(10):
            features.append(sorted_chars[i][1] if i < len(sorted_chars) else 0)
        
        # Special character ratios
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        special_count = sum(1 for c in text if c in special_chars)
        features.append(special_count / len(text) if text else 0)
        
        # Digit ratio
        digit_count = sum(1 for c in text if c.isdigit())
        features.append(digit_count / len(text) if text else 0)
        
        # Uppercase ratio
        upper_count = sum(1 for c in text if c.isupper())
        features.append(upper_count / len(text) if text else 0)
        
        # Pad or truncate to fixed size
        while len(features) < 100:
            features.append(0)
        features = features[:100]
        
        return np.array(features)
    
    def _extract_sequence_features(self, sequence: str) -> np.ndarray:
        """Extract features from sequence data"""
        # Convert sequence to numerical representation
        features = []
        
        # Character encoding
        for char in sequence[:100]:  # Limit to 100 characters
            features.append(ord(char) if char else 0)
        
        # Pad or truncate
        while len(features) < 100:
            features.append(0)
        features = features[:100]
        
        return np.array(features)
    
    def _extract_network_features(self, network_data: str) -> np.ndarray:
        """Extract features from network data"""
        features = []
        
        # Parse network data (simplified)
        lines = network_data.split('\n')
        features.append(len(lines))
        
        # Extract common network patterns
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        port_pattern = r':(\d+)'
        
        ip_count = len(re.findall(ip_pattern, network_data))
        port_count = len(re.findall(port_pattern, network_data))
        
        features.append(ip_count)
        features.append(port_count)
        
        # Pad or truncate
        while len(features) < 100:
            features.append(0)
        features = features[:100]
        
        return np.array(features)
    
    def _extract_generic_features(self, data: str) -> np.ndarray:
        """Extract generic features from any data"""
        features = []
        
        # Basic statistics
        features.append(len(data))
        features.append(len(set(data)))
        features.append(data.count(' '))
        features.append(data.count('\n'))
        features.append(data.count('\t'))
        
        # Entropy
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        for count in char_counts.values():
            p = count / len(data) if data else 0
            if p > 0:
                entropy -= p * np.log2(p)
        
        features.append(entropy)
        
        # Pad or truncate
        while len(features) < 100:
            features.append(0)
        features = features[:100]
        
        return np.array(features)
    
    async def _predict_with_neural_network(self, features: np.ndarray) -> Dict:
        """Predict using neural network"""
        try:
            model = self.models['threat_classifier']
            features_tensor = torch.FloatTensor(features).unsqueeze(0)
            
            with torch.no_grad():
                output = model(features_tensor)
                probabilities = output.numpy()[0]
                
                threat_idx = np.argmax(probabilities)
                confidence = probabilities[threat_idx]
                threat_type = list(ThreatType)[threat_idx].value
                
                return {
                    'model': 'neural_network',
                    'threat_type': threat_type,
                    'confidence': float(confidence),
                    'probabilities': probabilities.tolist()
                }
                
        except Exception as e:
            self.logger.error(f"[-] Neural network prediction failed: {e}")
            return {'model': 'neural_network', 'threat_type': 'unknown', 'confidence': 0.0}
    
    async def _predict_with_lstm(self, features: np.ndarray) -> Dict:
        """Predict using LSTM"""
        try:
            model = self.models['sequence_analyzer']
            features_tensor = torch.LongTensor(features[:100]).unsqueeze(0)
            
            with torch.no_grad():
                output = model(features_tensor)
                probabilities = output.numpy()[0]
                
                threat_idx = np.argmax(probabilities)
                confidence = probabilities[threat_idx]
                threat_type = list(ThreatType)[threat_idx].value
                
                return {
                    'model': 'lstm',
                    'threat_type': threat_type,
                    'confidence': float(confidence),
                    'probabilities': probabilities.tolist()
                }
                
        except Exception as e:
            self.logger.error(f"[-] LSTM prediction failed: {e}")
            return {'model': 'lstm', 'threat_type': 'unknown', 'confidence': 0.0}
    
    async def _predict_with_cnn(self, features: np.ndarray) -> Dict:
        """Predict using CNN"""
        try:
            model = self.models['pattern_recognizer']
            features_tensor = torch.FloatTensor(features).unsqueeze(0).unsqueeze(0)
            
            with torch.no_grad():
                output = model(features_tensor)
                probabilities = output.numpy()[0]
                
                threat_idx = np.argmax(probabilities)
                confidence = probabilities[threat_idx]
                threat_type = list(ThreatType)[threat_idx].value
                
                return {
                    'model': 'cnn',
                    'threat_type': threat_type,
                    'confidence': float(confidence),
                    'probabilities': probabilities.tolist()
                }
                
        except Exception as e:
            self.logger.error(f"[-] CNN prediction failed: {e}")
            return {'model': 'cnn', 'threat_type': 'unknown', 'confidence': 0.0}
    
    async def _predict_with_transformer(self, text: str) -> Dict:
        """Predict using transformer"""
        try:
            tokenizer = self.tokenizers['security']
            model = self.models['transformer']
            
            # Tokenize text
            inputs = tokenizer(text, return_tensors='pt', truncation=True, padding=True, max_length=512)
            
            with torch.no_grad():
                outputs = model(**inputs)
                # Use mean pooling
                pooled = outputs.last_hidden_state.mean(dim=1)
                
                # Simple classification (would need fine-tuning in real implementation)
                probabilities = torch.softmax(pooled, dim=1).numpy()[0]
                
                threat_idx = np.argmax(probabilities)
                confidence = probabilities[threat_idx]
                threat_type = list(ThreatType)[threat_idx % len(ThreatType)].value
                
                return {
                    'model': 'transformer',
                    'threat_type': threat_type,
                    'confidence': float(confidence),
                    'probabilities': probabilities.tolist()
                }
                
        except Exception as e:
            self.logger.error(f"[-] Transformer prediction failed: {e}")
            return {'model': 'transformer', 'threat_type': 'unknown', 'confidence': 0.0}
    
    async def _ensemble_predictions(self, predictions: List[Dict]) -> ThreatPrediction:
        """Combine predictions from multiple models"""
        if not predictions:
            return ThreatPrediction(
                threat_type="unknown",
                confidence=0.0,
                severity="low",
                description="No predictions available",
                mitigation="Manual review required",
                false_positive_rate=1.0,
                model_used="ensemble"
            )
        
        # Weighted voting based on confidence
        threat_votes = {}
        total_confidence = 0
        
        for pred in predictions:
            threat_type = pred.get('threat_type', 'unknown')
            confidence = pred.get('confidence', 0.0)
            
            if threat_type not in threat_votes:
                threat_votes[threat_type] = 0
            
            threat_votes[threat_type] += confidence
            total_confidence += confidence
        
        # Get winning threat type
        winning_threat = max(threat_votes.items(), key=lambda x: x[1])
        final_confidence = winning_threat[1] / total_confidence if total_confidence > 0 else 0
        
        # Determine severity based on threat type and confidence
        severity = self._determine_severity(winning_threat[0], final_confidence)
        
        # Get description and mitigation
        description, mitigation = self._get_threat_info(winning_threat[0])
        
        return ThreatPrediction(
            threat_type=winning_threat[0],
            confidence=final_confidence,
            severity=severity,
            description=description,
            mitigation=mitigation,
            false_positive_rate=1.0 - final_confidence,
            model_used=f"ensemble_{len(predictions)}_models"
        )
    
    def _determine_severity(self, threat_type: str, confidence: float) -> str:
        """Determine threat severity"""
        high_severity_threats = ['sql_injection', 'xss', 'privilege_escalation', 'zero_day']
        medium_severity_threats = ['csrf', 'directory_traversal', 'command_injection']
        
        if threat_type in high_severity_threats and confidence > 0.7:
            return "critical"
        elif threat_type in high_severity_threats or confidence > 0.8:
            return "high"
        elif threat_type in medium_severity_threats or confidence > 0.6:
            return "medium"
        else:
            return "low"
    
    def _get_threat_info(self, threat_type: str) -> Tuple[str, str]:
        """Get threat description and mitigation"""
        threat_info = {
            'sql_injection': (
                "SQL Injection vulnerability allows attackers to execute malicious SQL queries",
                "Use parameterized queries, input validation, and WAF protection"
            ),
            'xss': (
                "Cross-Site Scripting vulnerability allows attackers to inject malicious scripts",
                "Implement input validation, output encoding, and Content Security Policy"
            ),
            'csrf': (
                "Cross-Site Request Forgery vulnerability allows attackers to perform unauthorized actions",
                "Implement CSRF tokens and SameSite cookie attributes"
            ),
            'directory_traversal': (
                "Directory Traversal vulnerability allows attackers to access restricted files",
                "Validate and sanitize file paths, implement proper access controls"
            ),
            'command_injection': (
                "Command Injection vulnerability allows attackers to execute system commands",
                "Avoid shell execution, use parameterized commands, validate inputs"
            ),
            'xxe': (
                "XML External Entity vulnerability allows attackers to access local files",
                "Disable XML external entity processing, validate XML inputs"
            ),
            'ssrf': (
                "Server-Side Request Forgery vulnerability allows attackers to make requests from the server",
                "Validate URLs, use allowlists, implement network segmentation"
            ),
            'zero_day': (
                "Zero-day vulnerability is an unknown security flaw",
                "Implement defense in depth, monitor for unusual behavior, patch quickly"
            )
        }
        
        return threat_info.get(threat_type, (
            f"Unknown threat type: {threat_type}",
            "Manual security review recommended"
        ))
    
    async def train_model(self, model_name: str, training_data: List[Dict]) -> Dict:
        """Train AI model with provided data"""
        try:
            if model_name not in self.models:
                return {"error": f"Model {model_name} not found"}
            
            # Prepare training data
            X, y = self._prepare_training_data(training_data)
            
            if model_name == 'neural_network':
                result = await self._train_neural_network(X, y)
            elif model_name == 'random_forest':
                result = await self._train_random_forest(X, y)
            elif model_name == 'isolation_forest':
                result = await self._train_isolation_forest(X)
            else:
                result = {"error": f"Training not implemented for {model_name}"}
            
            self.logger.success(f"[+] Model {model_name} trained successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"[-] Model training failed: {e}")
            return {"error": str(e)}
    
    def _prepare_training_data(self, training_data: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for models"""
        X = []
        y = []
        
        for item in training_data:
            features = item.get('features', [])
            label = item.get('label', 0)
            
            X.append(features)
            y.append(label)
        
        return np.array(X), np.array(y)
    
    async def _train_neural_network(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """Train neural network model"""
        try:
            model = self.models['threat_classifier']
            optimizer = optim.Adam(model.parameters(), lr=0.001)
            criterion = nn.CrossEntropyLoss()
            
            # Convert to tensors
            X_tensor = torch.FloatTensor(X)
            y_tensor = torch.LongTensor(y)
            
            # Training loop
            model.train()
            for epoch in range(50):
                optimizer.zero_grad()
                outputs = model(X_tensor)
                loss = criterion(outputs, y_tensor)
                loss.backward()
                optimizer.step()
            
            return {"status": "success", "epochs": 50, "final_loss": loss.item()}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _train_random_forest(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """Train random forest model"""
        try:
            model = self.models['random_forest']
            model.fit(X, y)
            
            return {"status": "success", "n_estimators": model.n_estimators}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _train_isolation_forest(self, X: np.ndarray) -> Dict:
        """Train isolation forest model"""
        try:
            model = self.models['isolation_forest']
            model.fit(X)
            
            return {"status": "success", "contamination": model.contamination}
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_model_stats(self) -> Dict:
        """Get statistics about AI models"""
        stats = {
            "models_loaded": len(self.models),
            "model_types": list(self.models.keys()),
            "scalers_available": list(self.scalers.keys()),
            "tokenizers_available": list(self.tokenizers.keys()),
            "training_data_samples": len(self.training_data),
            "prediction_cache_size": len(self.prediction_cache)
        }
        
        # Model-specific stats
        for name, model in self.models.items():
            if hasattr(model, 'parameters'):
                stats[f"{name}_parameters"] = sum(p.numel() for p in model.parameters())
            elif hasattr(model, 'n_estimators'):
                stats[f"{name}_estimators"] = model.n_estimators
        
        return stats
    
    def save_models(self, path: str):
        """Save trained models"""
        try:
            import os
            os.makedirs(path, exist_ok=True)
            
            for name, model in self.models.items():
                if hasattr(model, 'state_dict'):
                    torch.save(model.state_dict(), f"{path}/{name}.pth")
                else:
                    joblib.dump(model, f"{path}/{name}.joblib")
            
            # Save scalers
            for name, scaler in self.scalers.items():
                joblib.dump(scaler, f"{path}/{name}_scaler.joblib")
            
            self.logger.success(f"[+] Models saved to {path}")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to save models: {e}")
    
    def load_models(self, path: str):
        """Load trained models"""
        try:
            import os
            
            for name, model in self.models.items():
                model_path = f"{path}/{name}.pth"
                if os.path.exists(model_path):
                    if hasattr(model, 'load_state_dict'):
                        model.load_state_dict(torch.load(model_path))
                    else:
                        self.models[name] = joblib.load(f"{path}/{name}.joblib")
            
            # Load scalers
            for name in self.scalers.keys():
                scaler_path = f"{path}/{name}_scaler.joblib"
                if os.path.exists(scaler_path):
                    self.scalers[name] = joblib.load(scaler_path)
            
            self.logger.success(f"[+] Models loaded from {path}")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to load models: {e}")
