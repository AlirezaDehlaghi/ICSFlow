

printStep(){
    echo ""
    echo ""
    echo "[" $1 "STARTED]"
    sleep 1
}

printStep "Getting last changes pull request"
sudo git pull
sleep 1

printStep "Check Requirement.txt"
pip install -r requirements.txt

printStep "Running ICSFlow with this arguments"

source="br_icsnet"
interval=0.5
predictor="input/ids.joblib"
target_file="output/sniffed.csv"
target_connection="input/connection.txt"




echo " "
echo "-E python3 src/ICSFlowGenerator.py sniff"
echo " source=" $source
echo " interval=" $interval
echo " predictor=" $predictor
echo " target_file=" $target_file
echo " target_connection=" $target_connection

printStep " "
 
#while true; do
sudo -E python3 src/ICSFlowGenerator.py sniff  --source $source --interval $interval  --predictor $predictor --target_file   $target_file --target_connection  $target_connection
#done
#sudo -E python3 src/ICSFlowGenerator.py sniff  --source br_icsnet --interval 0.5  --predictor input/ids.joblib --target_file   output/sniffed.csv --target_connection  input/connection.txt

#printStep "running with these arguments sniff  --source br_ics_net --interval 0.5 --predictor  input/predict_model.joblib   --target_file   output/sniffed.csv --target_connection  sample_connection.txt"
#python3 ICSFlowGenerator.py sniff  --source br_ics_net --interval 0.5 --predictor  input/predict_model.joblib   --target_file   output/sniffed.csv --target_connection  sample_connection.txt







