import random
import requests
import time
import torch
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bilstm_sqli.inference import load_model, translate_sentence
from rl_attacker.hybrid_agent import HybridAttackAgent

# --- Configuration ---
TARGET_URL = "http://127.0.0.1:5000/login"

def test_payload(payload):
    """Returns True if WAF bypassed (200 OK or 500 Error), False if blocked (403)."""
    try:
        r = requests.get(TARGET_URL, params={'q': payload}, timeout=0.1)
        # 200 = OK (WAF missed it), 500 = SQL Error (WAF missed it but DB crashed)
        if r.status_code == 200 or r.status_code == 500:
            return True
        return False
    except:
        return False

def run_benchmark():
    """
    Scientific Benchmark for IEEE Paper.
    Compares:
    1. Control Group: Standard SQL Injection Payloads.
    2. Experimental Group 1: DeepSQLi (BiLSTM) AI-Mutated Payloads.
    3. Experimental Group 2: Hybrid RL-BiLSTM (Adaptive Selection).
    
    Generates a Dual-Axis Chart (Efficiency vs Effectiveness).
    """
    print("--- Starting IEEE Benchmark ---")
    
    results = {}
    
    # 1. Group A: Control (Base Payloads)
    # The "Standard List" that every WAF blocks easily.
    print("\n[Group A: Control (Standard Payloads)]")
    from data.generator import BASE_PAYLOADS
    
    # Expand to 1000 samples for statistical significance
    control_payloads = []
    while len(control_payloads) < 1000:
        control_payloads.extend(BASE_PAYLOADS)
    control_payloads = control_payloads[:1000]
    
    start_time = time.time()
    success_count = 0
    for p in control_payloads:
        if test_payload(p):
            success_count += 1
    duration = time.time() - start_time
    
    results['Standard Attacks'] = {
        'Success Rate': (success_count / 1000) * 100, # %
        'Speed': duration # seconds
    }
    print(f"Success: {success_count}/1000 ({results['Standard Attacks']['Success Rate']}%) | Time: {duration:.2f}s")

    # 2. Group B: Experiment (BiLSTM)
    # The "AI Mutation" that adapts to the WAF.
    print("\n[Group B: Experiment (DeepSQLi BiLSTM)]")
    try:
        model, vocab, device = load_model()
        
        start_time = time.time()
        success_count = 0
        
        # Fair Test: Use the SAME base payloads, but mutate them
        for i in range(1000):
            base = control_payloads[i] # One-to-one mapping
            
            # The AI "Thinks" (Mutates)
            attack = translate_sentence(base, model, vocab, device)
            
            if test_payload(attack):
                success_count += 1
                
        duration = time.time() - start_time
        
        results['DeepSQLi (AI)'] = {
            'Success Rate': (success_count / 1000) * 100, # %
            'Speed': duration # seconds
        }
        print(f"Success: {success_count}/1000 ({results['DeepSQLi (AI)']['Success Rate']}%) | Time: {duration:.2f}s")
        
    except Exception as e:
        print(f"BiLSTM Failed: {e}")
        results['DeepSQLi (AI)'] = {'Success Rate': 0, 'Speed': 0}

    # 3. Group C: Experiment (Hybrid RL-BiLSTM)
    # The "Adaptive AI" that learns which mutations work best.
    print("\n[Group C: Experiment (Hybrid RL-BiLSTM)]")
    try:
        # Initialize hybrid agent and load best Q-table
        agent = HybridAttackAgent(firewall_url=TARGET_URL)
        if not agent.load(use_best=True):
            print("Warning: No best Q-table found, using final Q-table")
            agent.load(use_best=False)
        
        start_time = time.time()
        success_count = 0
        
        # Fair Test: Use the SAME base payloads
        for i in range(1000):
            base = control_payloads[i]
            
            # The Hybrid AI "Thinks" (Generates candidates + Selects best)
            result = agent.attack_single(base, learn=False)
            
            if result['bypassed']:
                success_count += 1
                
        duration = time.time() - start_time
        
        results['Hybrid RL-BiLSTM'] = {
            'Success Rate': (success_count / 1000) * 100,
            'Speed': duration
        }
        print(f"Success: {success_count}/1000 ({results['Hybrid RL-BiLSTM']['Success Rate']}%) | Time: {duration:.2f}s")
        
    except Exception as e:
        print(f"Hybrid RL-BiLSTM Failed: {e}")
        import traceback
        traceback.print_exc()
        results['Hybrid RL-BiLSTM'] = {'Success Rate': 0, 'Speed': 0}

    print("\n--- Final Results ---")
    print(results)
    
    # --- Scientific Visualization ---
    try:
        import matplotlib.pyplot as plt
        import numpy as np
        
        labels = list(results.keys())
        success_rates = [results[l]['Success Rate'] for l in labels]
        speeds = [results[l]['Speed'] for l in labels]
        
        x = np.arange(len(labels))
        width = 0.5
        
        # Professional IEEE-Style Figure
        fig, ax1 = plt.subplots(figsize=(8, 6))
        
        # Left Axis: Effectiveness (Bar Chart) - Different colors for each bar
        colors = ['#7f8c8d', '#3498db', '#2ecc71']  # Gray, Blue, Green
        bars = ax1.bar(x, success_rates, width, color=colors, alpha=0.85, 
                      edgecolor='black', linewidth=1.5)
        ax1.set_ylabel('Bypass Success Rate (%)', color='#2c3e50', fontweight='bold', fontsize=12)
        ax1.tick_params(axis='y', labelcolor='#2c3e50')
        ax1.set_ylim(0, 105)
        ax1.grid(axis='y', linestyle='--', alpha=0.3)
        
        # Right Axis: Efficiency (Line Chart)
        ax2 = ax1.twinx()
        line = ax2.plot(x, speeds, label='Generation Time (s)', color='#e74c3c', 
                       marker='D', markersize=8, linewidth=2.5, linestyle='-')
        ax2.set_ylabel('Time per 1000 Attacks (s)', color='#c0392b', fontweight='bold', fontsize=12)
        ax2.tick_params(axis='y', labelcolor='#c0392b')
        ax2.set_ylim(0, max(speeds) * 1.3 if max(speeds) > 0 else 10)
        
        # X-Axis & Title
        ax1.set_xticks(x)
        ax1.set_xticklabels(['Standard\nAttacks', 'BiLSTM\n(DeepSQLi)', 'Hybrid\nRL-BiLSTM'], 
                           fontweight='bold', fontsize=11)
        plt.title('Performance Comparison: Standard vs AI-Augmented Attacks', 
                 fontsize=14, fontweight='bold', pad=20)
        
        # Data Labels on bars
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{height:.1f}%',
                    ha='center', va='bottom', fontweight='bold', fontsize=11)
        
        # Data Labels on line points
        for i, (xi, speed) in enumerate(zip(x, speeds)):
            ax2.text(xi, speed + max(speeds) * 0.08, f'{speed:.1f}s',
                    ha='center', va='bottom', fontweight='bold', fontsize=10,
                    bbox=dict(boxstyle='round,pad=0.4', facecolor='white', 
                             edgecolor='#c0392b', linewidth=1.5))
                    
        # Legend (Combined)
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#95a5a6', edgecolor='black', label='Success Rate', linewidth=1.5),
            plt.Line2D([0], [0], color='#e74c3c', marker='D', linestyle='-', 
                      markersize=8, linewidth=2.5, label='Generation Time')
        ]
        ax1.legend(handles=legend_elements, loc='upper left', fontsize=11, framealpha=0.95)
        
        plt.tight_layout()
        plt.savefig('benchmark/benchmark_results.png', dpi=300, bbox_inches='tight')
        print("Generated Academic Chart: benchmark/benchmark_results.png")
        
    except ImportError:
        print("Matplotlib not installed. Skipping graph.")

if __name__ == "__main__":
    run_benchmark()
