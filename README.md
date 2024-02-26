Air Quality Checker
The Air Quality Checker is a web application designed to provide real-time monitoring and reporting of air quality observations. Developed using Flask, the application integrates OAuth2 authentication with Google, ensuring secure user access. Users can submit pollution reports, detailing the location, pollution type, and additional comments. The project leverages the AQI (Air Quality Index) data from aqicn.org/waqi.info for real-time monitoring.

Features
OAuth2 Integration: The application securely authenticates users through Google OAuth2, managing user sessions and credentials effectively.

Real-Time Air Quality Monitoring: Integration with aqicn.org/waqi.info enables the application to fetch real-time air quality data, offering users up-to-date information.

Database Management: The project utilizes SQLite for database interactions, ensuring simplicity and ease of migration with Flask's migrate command.

Improvements and Scalability
To enhance API performance and scalability, the project can implement a caching mechanism for frequently requested data. Additionally, optimizing database queries and considering a more robust database solution like PostgreSQL or MySQL can contribute to improved overall performance. Exploring forecasting capabilities by incorporating external endpoints and utilizing machine learning prediction algorithms is a potential enhancement.

