import csv
import matplotlib.pyplot as plt
import japanize_matplotlib
import math

def calc_response_time_stats(filename):
    response_times = []
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            response_times.append(float(row['Response Time']))
    
    mean = sum(response_times) / len(response_times)
    variance = sum([(x - mean) ** 2 for x in response_times]) / len(response_times)
    std_dev = math.sqrt(variance)
    
    return mean, std_dev

# CSVファイルのパスを指定
baseline_signin_csv = "./evaluation/data/performance/response_time/baseline/response_times_signin.csv"
proposed_signin_csv = "./evaluation/data/performance/response_time/proposed/response_times_signin.csv"
baseline_after_signin_csv = "./evaluation/data/performance/response_time/baseline/response_times_after_signin.csv"
proposed_after_signin_csv = "./evaluation/data/performance/response_time/proposed/response_times_after_signin.csv"
proposed_after_signin_confidential_csv = "./evaluation/data/performance/response_time/proposed/response_times_after_signin_confidential.csv"

# CSVファイルから平均と標準偏差を計算
mean_baseline_signin, std_baseline_signin = calc_response_time_stats(baseline_signin_csv)
mean_proposed_signin, std_proposed_signin = calc_response_time_stats(proposed_signin_csv)
mean_baseline_after_signin, std_baseline_after_signin = calc_response_time_stats(baseline_after_signin_csv)
mean_proposed_after_signin, std_proposed_after_signin = calc_response_time_stats(proposed_after_signin_csv)
mean_proposed_after_signin_confidential, std_proposed_after_signin_confidential = calc_response_time_stats(proposed_after_signin_confidential_csv)

# グラフを描画
labels = ['導入前\n（認証時）', '導入後\n（認証時）', '導入前\n（認証後）', '導入後\n（認証後）', '導入後\n（認証後,機密）']
values = [mean_baseline_signin*1000, mean_proposed_signin*1000, mean_baseline_after_signin*1000, mean_proposed_after_signin*1000, mean_proposed_after_signin_confidential*1000]
std_devs = [std_baseline_signin*1000, std_proposed_signin*1000, std_baseline_after_signin*1000, std_proposed_after_signin*1000, std_proposed_after_signin_confidential*1000]
colors = ['gainsboro', 'darkgray', 'lightgray', 'grey', 'dimgray']

legend_labels = ['提案手法導入前の認証時リクエスト', '提案手法導入後の認証時リクエスト', '提案手法導入前の認証後リクエスト', '提案手法導入後の認証後リクエスト', '提案手法導入後の認証後機密リクエスト']

plt.tick_params(labelsize=12)
bars = plt.bar(labels, values, color=colors, yerr=std_devs, capsize=5)
for bar, legend_label in zip(bars, legend_labels):
    bar.set_label(legend_label)
plt.ylabel('応答時間 [ms]', fontsize=14)
plt.legend()

# グラフをファイルとして保存
output_filename = "./evaluation/graph/response_times_comparison.png"
plt.savefig(output_filename, format="png", dpi=300)
print(f"Graph saved to {output_filename}")

plt.close()