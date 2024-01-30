# DDoS Detection Using OC-SVM Algorithm

This repository contains the implementation of the One-Class Support Vector Machine (OC-SVM) algorithm for detecting Distributed Denial of Service (DDoS) attacks, specifically SYN flood attacks, using network traffic data. This project is part of my Master's thesis at the Institute of Engineering and Science, Portugal (ISEP), under the supervision of Prof. Yousrah Chouchoub.

## Project Overview

The project's goal is to develop an effective method for detecting DDoS attacks by analyzing network traffic data to identify abnormal patterns indicative of SYN flood attacks using the OC-SVM algorithm.

## Environment Setup

### Hardware Specifications

- **Processor:** Intel Xeon CPU with 8 cores, allowing for concurrent processing of large datasets.
- **Memory:** 16GB DDR4 RAM, providing sufficient memory to handle large-scale data without significant swapping or slowdown.
- **Storage:** 500GB SSD, ensuring quick read/write operations for the dataset, crucial for processing over 4 million rows.

### Software Specifications

- **Operating Systems:** Linux, Windows 8 or above.
- **Programming Language:** Python 3.8, chosen for its extensive support libraries and suitability for data analysis and machine learning tasks.
- **Development Environment:** PyCharm for more structured coding and application development.
- **Key Libraries:** pandas for data manipulation and analysis, scikit-learn for accessing the OneClassSVM, and Matplotlib for visualization.

## Data Collection and Preparation

### Dataset Description

- **Source:** TCP dump data from Orange Labs.
- **Content:** Over 4 million rows of network traffic records with 16 columns.
- **Features:** Includes destination and source addresses, ports, protocol numbers, timestamps, packet numbers, TCP flags, etc.
- **Preprocessing:** Conversion of UNIX epoch time to datetime, encoding of categorical data, and sorting.

## Implementation Details

### Scope

The implementation uses One-Class Support Vector Machine (OC-SVM) for analyzing network traffic data, focusing on processing and analyzing data to detect anomalies and emphasizing the detection of SYN flooding attacks.

### Feature Engineering and Model Training

- **Feature Selection:** Focusing on destination IP addresses and timestamps.
- **Sliding Window Technique:** 120 seconds (3 minutes) for segmenting data.
- **OC-SVM Algorithm:** RBF kernel, gamma set to 'auto', and nu set to 0.0026.
- **Anomaly Detection:** Using OC-SVM to identify deviations from normal traffic.

### SYN Packet Analysis for Flooding Detection

- **Filtering and Analysis:** Focusing on SYN packets and their occurrence across the identified anomalous windows.

## Results and Discussion

### SYN Flooding Attack Analysis

- **Major Findings:** High packet counts and diverse source IPs indicating SYN flooding attacks.
- **Temporal Patterns:** Insights into the timing and duration of attacks.
- **Discussion:** Valuable insights into SYN flooding attacks, including potential vulnerabilities and behavior of attackers.

## Limitations and Future Work

- **False Positives/Negatives:** Potential for inaccuracies requiring further refinement.
- **Dynamic Nature of Attacks:** Need for continuous update and adaptation to new attack methodologies.
- **Broader Scope of DDoS Attack Vectors:** Expanding the scope to include other types of DDoS attacks.
- **Real-time Detection:** Integrating the system for real-time detection.

## Conclusion

This project successfully demonstrates the potential of using the OC-SVM model for detecting DDoS attacks within network traffic data, providing significant insights for network security enhancements.

## Acknowledgements

I extend my deepest gratitude to Prof. Yousrah Chouchoub for her invaluable guidance and supervision throughout this research endeavor.

## Contact

- Abubakar Umar Elnafaty
- Email: abubakar-umar.el-nafaty@eleve.isep.fr
- LinkedIn: www.linkedin.com/in/abubakar-umar-elnafaty-17a2a5133
- 

---

© Abubakar Elnafaty , 2024. All Rights Reserved.
