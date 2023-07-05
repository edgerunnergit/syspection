use std::{time::SystemTime, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
pub struct Stream {
    uuid: String,
    label: String,
}

#[derive(Serialize, Deserialize)]
pub struct StreamData {
    stream: Stream,
    values: Vec<[String; 2]>,
}

#[derive(Serialize, Deserialize)]
pub struct Data {
    streams: Vec<StreamData>,
}

#[derive(Debug, Deserialize)]
struct Response {
    status: String,
    msg: String,
    data: Data2,
}

#[derive(Debug, Deserialize)]
struct Data2 {
    token: String,
    token_status: String,
    is_update_available: bool,
}

pub async fn send_logs(api: &String, values: Vec<[String; 2]>) -> Result<(), reqwest::Error> {
    let barer = format!("Bearer {}", api);
    let mut headers = reqwest::header::HeaderMap::new();

    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("Authorization", barer.parse().unwrap());

    let stream = Stream {
        uuid: String::from("v0-ssh-ips-uuid"),
        label: String::from("v0-ssh-ips-label"),
    };

    let stream_data = StreamData { stream, values };

    let data = Data {
        streams: vec![stream_data],
    };

    let json_data = json!({
        "data": data,
    });

    println!("{}", serde_json::to_string_pretty(&json_data).unwrap());

    // send the data to the server
    let client = reqwest::Client::new();
    let res = client
        .post("https://test.one.subcom.link/api/v2/logs/push")
        .headers(headers)
        .json(&json_data)
        .send()
        .await?;

    // Handle the response as needed
    println!("Response status: {}", res.status());

    // print the response
    println!("{:#?}", res.text().await?);

    Ok(())
}

pub async fn get_auth(api: String) -> Result<(Arc<String>, SystemTime), reqwest::Error> {
    let now = SystemTime::now();
    let barer = format!("Bearer {}", api);
    let mut headers = reqwest::header::HeaderMap::new();

    headers.insert("Authorization", barer.parse().unwrap());

    // send the data to the server
    let client = reqwest::Client::new();
    let res = client
        .get("https://test.one.subcom.link/api/v2/auth")
        .headers(headers)
        .send()
        .await?;

    // Handle the response as needed
    println!("Response status: {}", res.status());
    println!("A new token has been requested");

    // get the reponse as json
    let res: Response = res.json().await?;

    Ok((Arc::new(res.data.token), now))
    // Ok(res.text().await?)
}