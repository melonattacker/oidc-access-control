import csv
import matplotlib.pyplot as plt
import japanize_matplotlib
import statistics

def remove_outliers(data):
    mean = statistics.mean(data)
    std = statistics.stdev(data)
    return [x for x in data if abs((x - mean) / std) < 3]

def calc_avg_and_std(filename, key):
    values = []
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            values.append(float(row[key]))
    filtered_values = remove_outliers(values)
    print(f"{filename}: {values}, {filtered_values}")
    return statistics.mean(filtered_values), statistics.stdev(filtered_values)

def plot_and_save_graph(labels, values, errors, y_label, filename, legend_labels):
    plt.tick_params(labelsize=10)
    bars = plt.bar(labels, values, color=['gainsboro', 'darkgray', 'lightgray', 'grey', 'dimgray'], yerr=errors, capsize=5)
    for bar, legend_label in zip(bars, legend_labels):
        bar.set_label(legend_label)
    plt.ylabel(y_label, fontsize=14)
    plt.legend(fontsize=12)
    plt.savefig(filename, format="png", dpi=300)
    plt.clf()

# CSVファイルのパス
baseline_signin_csv = "./evaluation/data/performance/resource/baseline/resource_signin.csv"
proposed_signin_csv = "./evaluation/data/performance/resource/proposed/resource_signin.csv"
baseline_after_signin_csv = "./evaluation/data/performance/resource/baseline/resource_after_signin.csv"
proposed_after_signin_csv = "./evaluation/data/performance/resource/proposed/resource_after_signin.csv"
proposed_after_signin_confidential_csv = "./evaluation/data/performance/resource/proposed/resource_after_signin_confidential.csv"

# CSVファイルからデータを計算
labels = ['Without\n(Auth)', 'With\n(Auth)', 'Without\n(Post-Auth)', 'With\n(Post-Auth)', 'With\n(Post-Auth,\nConfidential)']
cpu_values = []
cpu_errors = []
mem_values = []
mem_errors = []

for csv_file in [baseline_signin_csv, proposed_signin_csv, baseline_after_signin_csv, proposed_after_signin_csv, proposed_after_signin_confidential_csv]:
    avg_cpu, std_cpu = calc_avg_and_std(csv_file, 'CPU Usage (%)')
    avg_mem, std_mem = calc_avg_and_std(csv_file, 'Memory Usage (MB)')
    cpu_values.append(avg_cpu)
    cpu_errors.append(std_cpu)
    print(f"CPU: avg:{avg_cpu}, std:{std_cpu}")
    mem_values.append(avg_mem)
    mem_errors.append(std_mem)

legend_labels = ['Auth request without the method', 'Auth request with the method', 'Post auth request without the method', 'Post auth request with the method', 'Post auth confidential request with the method']

# CPU使用率のグラフを描画 & 保存
plot_and_save_graph(labels, cpu_values, cpu_errors, 'CPU Usage [%]', './evaluation/graph/cpu_usage_comparison_en_updated.png', legend_labels)

# メモリ使用量のグラフを描画 & 保存
plot_and_save_graph(labels, mem_values, mem_errors, 'Memory Usage [MB]', './evaluation/graph/memory_usage_comparison_en_updated.png', legend_labels)