

printStep(){
    echo ""
    echo ""
    echo "[" $1 "STARTED]"
    sleep 1
}

printStep "Getting last changes pull request"
sudo git pull

printStep "Check Requirement.txt"
pip install -r requirements.txt

printStep "Running ICSFlow with this arguments"

source = "br_icsnet"
interval = 0.5
predictor = "input/ids.joblib"
target_file ="output/sniffed.csv"
target_connection = "input/connection.txt"




echo " "
echo "-E python3 src/ICSFlowGenerator.py sniff"
echo "\t --source" source
echo "\t --interval" interval
echo "\t --predictor" predictor
echo "\t --target_file" target_file
echo "\t --target_connection" target_connection

printStep " "

sudo -E python3 src/ICSFlowGenerator.py sniff  --source source --interval interval  --predictor predictor --target_file   target_file --target_connection  target_connection
#sudo -E python3 src/ICSFlowGenerator.py sniff  --source br_icsnet --interval 0.5  --predictor input/ids.joblib --target_file   output/sniffed.csv --target_connection  input/connection.txt

#printStep "running with these arguments sniff  --source br_ics_net --interval 0.5 --predictor  input/predict_model.joblib   --target_file   output/sniffed.csv --target_connection  sample_connection.txt"
#python3 ICSFlowGenerator.py sniff  --source br_ics_net --interval 0.5 --predictor  input/predict_model.joblib   --target_file   output/sniffed.csv --target_connection  sample_connection.txt







