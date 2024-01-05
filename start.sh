

printStep(){
    echo ""
    echo ""
    echo "[" $1 "STARTED]"
    sleep 1 
}

#printStep "Check Requirement.txt"
#pip install -r requirements.txt 

printStep "Running ICSFlow with this arguments:"

printStep ""

sudo -E python3 src/ICSFlowGenerator.py sniff  --source br_icsnet --interval 0.5  --predictor input/ids.joblib --target_file   output/sniffed.csv --target_connection  input/sample_connection.txt

#printStep "running with these arguments sniff  --source br_ics_net --interval 0.5 --predictor  input/predict_model.joblib   --target_file   output/sniffed.csv --target_connection  sample_connection.txt"
#python3 ICSFlowGenerator.py sniff  --source br_ics_net --interval 0.5 --predictor  input/predict_model.joblib   --target_file   output/sniffed.csv --target_connection  sample_connection.txt



