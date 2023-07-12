use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Stream {
    pub uuid: String,
    pub label: String,
}

#[derive(Serialize, Deserialize)]
pub struct StreamData {
    pub stream: Stream,
    pub values: Vec<[String; 2]>,
}

#[derive(Serialize, Deserialize)]
pub struct LogData {
    pub streams: Vec<StreamData>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Response {
    pub status: String,
    pub msg: String,
    pub data: Data,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Data {
    pub token: String,
    pub token_status: String,
    // pub _is_update_available: bool,
}