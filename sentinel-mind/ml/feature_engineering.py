import numpy as np

def extract_flow_features(flow: dict) -> np.ndarray:
    """
    Extract 20 features from a raw network flow record.
    Compatible with CICIDS2017/2018 dataset columns.
    """
    features = [
        flow.get("dst_port", 0) / 65535,
        flow.get("flow_duration", 0) / 1e8,
        flow.get("fwd_packets", 0) / 10000,
        flow.get("bwd_packets", 0) / 10000,
        flow.get("fwd_bytes", 0) / 1e6,
        flow.get("bwd_bytes", 0) / 1e6,
        flow.get("flow_bytes_per_sec", 0) / 1e6,
        flow.get("flow_packets_per_sec", 0) / 10000,
        flow.get("fwd_iat_mean", 0) / 1e6,
        flow.get("bwd_iat_mean", 0) / 1e6,
        flow.get("psh_flag_count", 0) / 10,
        flow.get("ack_flag_count", 0) / 100,
        flow.get("syn_flag_count", 0) / 10,
        flow.get("fin_flag_count", 0) / 10,
        flow.get("down_up_ratio", 0) / 100,
        flow.get("avg_packet_size", 0) / 1500,
        flow.get("fwd_segment_size_avg", 0) / 1500,
        flow.get("active_mean", 0) / 1e7,
        flow.get("idle_mean", 0) / 1e8,
        1.0 if flow.get("protocol") == "TCP" else 0.0,
    ]
    return np.clip(np.array(features, dtype=np.float32), 0, 1)