import csv
import matplotlib.pyplot as plt
import japanize_matplotlib
import statistics

def calc_avg_and_std(filename, key):
    values = []
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            values.append(float(row[key]))
    return statistics.mean(values), statistics.stdev(values)

def plot_and_save_graph(labels, values, errors, y_label, filename):
    plt.tick_params(labelsize=12)
    plt.bar(labels, values, color=['lightgray', 'grey', 'lightgray', 'grey', 'grey'], yerr=errors, capsize=5)
    plt.ylabel(y_label, fontsize=14)
    plt.savefig(filename, format="png", dpi=300)
    plt.clf()

# CSVファイルのパス
baseline_signin_csv = "./evaluation/data/performance/resource/baseline/resource_signin.csv"
proposed_signin_csv = "./evaluation/data/performance/resource/proposed/resource_signin.csv"
baseline_after_signin_csv = "./evaluation/data/performance/resource/baseline/resource_after_signin.csv"
proposed_after_signin_csv = "./evaluation/data/performance/resource/proposed/resource_after_signin.csv"
proposed_after_signin_confidential_csv = "./evaluation/data/performance/resource/proposed/resource_after_signin_confidential.csv"

# CSVファイルからデータを計算
labels = ['導入前\n（認証時）', '導入後\n（認証時）', '導入前\n（認証後）', '導入後\n（認証後）', '導入後\n（認証後, 機密）']
cpu_values = []
cpu_errors = []
mem_values = []
mem_errors = []

for csv_file in [baseline_signin_csv, proposed_signin_csv, baseline_after_signin_csv, proposed_after_signin_csv, proposed_after_signin_confidential_csv]:
    avg_cpu, std_cpu = calc_avg_and_std(csv_file, 'CPU Usage (%)')
    avg_mem, std_mem = calc_avg_and_std(csv_file, 'Memory Usage (MB)')
    cpu_values.append(avg_cpu)
    cpu_errors.append(std_cpu)
    mem_values.append(avg_mem)
    mem_errors.append(std_mem)

# CPU使用率のグラフを描画 & 保存
plot_and_save_graph(labels, cpu_values, cpu_errors, 'CPU使用率 [%]', './evaluation/graph/cpu_usage_comparison.png')

# メモリ使用量のグラフを描画 & 保存
plot_and_save_graph(labels, mem_values, mem_errors, 'メモリ使用量 [MB]', './evaluation/graph/memory_usage_comparison.png')