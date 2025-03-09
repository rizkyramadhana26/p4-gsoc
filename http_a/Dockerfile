# Stage 1: Build Stage
FROM ubuntu

# Set the working directory in the container
WORKDIR /app

# Copy the application code
COPY . .

# Install required packages
RUN apt-get update && apt-get install python3 python3-requests tshark -y

# Expose the port the application will run on
EXPOSE 8000

# Define the command to run the application
CMD ["python3", "server.py"]
