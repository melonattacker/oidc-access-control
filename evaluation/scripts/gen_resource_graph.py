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

def plot_and_save_graph(labels, values, errors, y_label, filename, legend_labels):
    plt.tick_params(labelsize=12)
    bars = plt.bar(labels, values, color=['gainsboro', 'darkgray', 'lightgray', 'grey', 'dimgray'], yerr=errors, capsize=5)
    for bar, legend_label in zip(bars, legend_labels):
        bar.set_label(legend_label)
    plt.ylabel(y_label, fontsize=14)
    plt.legend()
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

legend_labels = ['提案手法導入前の認証時リクエスト', '提案手法導入後の認証時リクエスト', '提案手法導入前の認証後リクエスト', '提案手法導入後の認証後リクエスト', '提案手法導入後の認証後機密リクエスト']

# CPU使用率のグラフを描画 & 保存
plot_and_save_graph(labels, cpu_values, cpu_errors, 'CPU使用率 [%]', './evaluation/graph/cpu_usage_comparison.png', legend_labels)

# メモリ使用量のグラフを描画 & 保存
plot_and_save_graph(labels, mem_values, mem_errors, 'メモリ使用量 [MB]', './evaluation/graph/memory_usage_comparison.png', legend_labels)