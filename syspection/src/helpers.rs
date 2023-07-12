use serde_json::json;
use std::{time::SystemTime, sync::Arc};

use crate::model::{Stream, StreamData, LogData, Response};

pub async fn send_logs(api: &String, values: Vec<[String; 2]>) -> Result<(), reqwest::Error> {
    println!("Sending logs to the server");
    let barer = format!("Bearer {}", api);
    let mut headers = reqwest::header::HeaderMap::new();

    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("Authorization", barer.parse().unwrap());

    let stream = Stream {
        uuid: String::from("v1-ssh-ips-uuid"),
        label: String::from("v1-ssh-ips-label"),
    };

    let stream_data = StreamData { stream, values };

    let data = LogData {
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