// SPDX-License-Identifier: Apache-2.0
use actix_web::{web, App, HttpServer, Responder, HttpResponse};

async fn index() -> impl Responder {
    HttpResponse::Ok().body(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Protected Service</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                text-align: center;
            }
            .container {
                background: #f9f9f9;
                border-radius: 8px;
                padding: 20px;
                margin-top: 40px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            h1 {
                color: #2c3e50;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Protected Content</h1>
            <p>If you can see this page, you have successfully authenticated through Runegate!</p>
        </div>
    </body>
    </html>
    "#)
}

async fn api_data() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "This is protected API data",
        "data": {
            "items": [
                {"id": 1, "name": "Item 1"},
                {"id": 2, "name": "Item 2"},
                {"id": 3, "name": "Item 3"}
            ]
        }
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Starting test target service on http://127.0.0.1:7860");
    
    HttpServer::new(|| {
        App::new()
            .service(web::resource("/").route(web::get().to(index)))
            .service(web::resource("/api/data").route(web::get().to(api_data)))
    })
    .bind("127.0.0.1:7860")?
    .workers(2)
    .run()
    .await
}
