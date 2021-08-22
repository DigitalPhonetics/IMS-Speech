#!/bin/bash

set -e
set -u
set -o pipefail

LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}"
PS1="${PS1:-}"
PYTHONPATH="${PYTHONPATH:-}"

file=$(realpath "$1")
language=$2
recid=$(basename "${file}" | md5sum | awk '{print $1}')

basedir=$(realpath $(dirname $0))
workdir=$(mktemp -d)
model=/home/ims/models/${language}
espnet=/home/ims/espnet

# Segment the audio
mkdir -p ${workdir}/data/${recid}
duration=$(
	ffmpeg -i "${file}" -acodec pcm_s16le -ar 16000 -ac 1 ${workdir}/data/${recid}.wav 2>&1 | \
	grep Duration | \
	perl -p -e 'my ($h, $m, $s) = ($_ =~ /(\d\d):(\d\d):(\d\d\.\d\d)/); $_ = $h * 3600 + $m * 60 + $s;'
)
if (( $(echo "$duration > 30.0" |bc -l) )); then
	# Segment the audio
	echo "${recid} sox ${workdir}/data/${recid}.wav -t wav -r 8k - |" > ${workdir}/data/${recid}/wav.scp
	echo "${recid} ${recid}" > ${workdir}/data/${recid}/utt2spk
	echo "${recid} ${recid}" > ${workdir}/data/${recid}/spk2utt
	cd ${espnet}/tools/kaldi/egs/aspire/s5

	steps/segmentation/detect_speech_activity.sh \
		--cmd run.pl \
		--nj 1 \
		--convert-data-dir-to-whole false \
		--graph-opts "--min-silence-duration=0.5 --min-speech-duration=1.0 --max-speech-duration=30.0" \
		--transform-probs-opts "--sil-scale=0.1" \
		--extra-left-context 79 \
		--extra-right-context 21 \
		--frames-per-chunk 150 \
		--extra-left-context-initial 0 \
		--extra-right-context-final 0 \
		--acwt 0.3 \
		--merge-consecutive-max-dur 10.0 \
		--segment_padding 0.1 \
		${workdir}/data/${recid} \
		$(dirname ${model})/tdnn_stats_asr_sad_1a \
		${workdir}/mfcc_hires \
		${workdir}/segmentation \
		${workdir}/segmentation/${recid}

	cp ${workdir}/segmentation/${recid}_seg/segments ${workdir}/data/${recid}/
	awk '{print $1" text"}' ${workdir}/data/${recid}/segments > ${workdir}/data/${recid}/text
	awk '{print $1" "$1}' ${workdir}/data/${recid}/segments > ${workdir}/data/${recid}/utt2spk
	utils/fix_data_dir.sh ${workdir}/data/${recid}

	(
	cd ${espnet}/tools/kaldi/egs/callhome_diarization/v2
	. path.sh

	steps/make_mfcc.sh \
		--mfcc-config conf/mfcc.conf \
		--nj 1 \
		--cmd run.pl \
		--write-utt2num-frames true \
		${workdir}/data/${recid} \
		${workdir}/make_mfcc \
		${workdir}/mfcc

	diarization/nnet3/xvector/extract_xvectors.sh \
		--cmd run.pl \
		--nj 1 \
		--window 1.5 \
		--period 0.75 \
		--apply-cmn false \
		--min-segment 0.5 \
		$(dirname ${model})/xvector_nnet_1a \
		${workdir}/data/${recid} \
		${workdir}/diarization

	diarization/nnet3/xvector/score_plda.sh \
		--cmd run.pl \
		--nj 1 \
		$(dirname ${model})/xvector_nnet_1a/xvectors_callhome2 \
		${workdir}/diarization \
		${workdir}/diarization

	diarization/cluster.sh \
		--cmd run.pl \
		--nj 1 \
		--threshold -0.6 \
		${workdir}/diarization \
		${workdir}/diarization

	rm ${workdir}/data/${recid}/utt2* ${workdir}/data/${recid}/feats.scp ${workdir}/data/${recid}/spk2utt
	e=$(awk '{ e = $4 + $5 } END {print e}' ${workdir}/diarization/rttm)
	awk -v em=$e -v pad=0.3 \
		'{s = $4 > pad ? $4 - pad : 0; e = $4 + $5 + pad < em ? $4 + $5 + pad : em; printf("%s-%07d-%07d %s %.3f %.3f\n", $2, s * 100, e * 100, $2, s, e);}' \
		${workdir}/diarization/rttm > ${workdir}/data/${recid}/segments
	)
	cd ${basedir}
else
	echo "${recid} ${duration}" | \
		awk '{printf("%s-%08d-%08d %s %.3f %.3f\n", $1, 0, $2 * 100, $1, 0, $2);}' \
		> ${workdir}/data/${recid}/segments
fi

# Recognize the speech
echo "${recid} ${workdir}/data/${recid}.wav" > ${workdir}/data/${recid}/wav.scp
awk '{print $1" text"}' ${workdir}/data/${recid}/segments > ${workdir}/data/${recid}/text
awk '{print $1" "$1}' ${workdir}/data/${recid}/segments > ${workdir}/data/${recid}/utt2spk
cd ${espnet}/egs/librispeech/asr1/
. ./path.sh
export OMP_NUM_THREADS=48
decode_cmd=run.pl
nj=$(cat <(wc -l ${workdir}/data/${recid}/segments | awk '{print $1}') <(grep -c vendor_id /proc/cpuinfo) | sort -g | head -n1)
utils/fix_data_dir.sh ${workdir}/data/${recid}
steps/make_fbank_pitch.sh --cmd ${decode_cmd} --nj ${nj} --write_utt2num_frames true ${workdir}/data/${recid} ${workdir}/feats/${recid}
utils/fix_data_dir.sh ${workdir}/data/${recid}
dumpdir=${workdir}/dump/${recid}
dump.sh --cmd ${decode_cmd} --nj ${nj} --do_delta false ${workdir}/data/${recid}/feats.scp ${model}/cmvn.ark ${workdir}/exp/${recid} ${dumpdir}
data2json.sh --feat ${dumpdir}/feats.scp --bpecode ${model}/bpe.model ${workdir}/data/${recid} ${model}/units.txt > ${dumpdir}/data.json
asr_recog.py \
	--backend pytorch \
	--recog-json ${dumpdir}/data.json \
	--result-label ${dumpdir}/result.json \
	--model ${model}/asr/model.dat  \
	--rnnlm ${model}/lm/model.dat \
        --debugmode 0 \
        --verbose 0 \
	--api v2 \
        --quantize-asr-model true \
        --quantize-lm-model true \
        --config ${model}/decode.yaml

json2trn.py ${dumpdir}/result.json ${model}/units.txt --num-spkrs 1 --refs ${dumpdir}/ref.trn --hyps ${dumpdir}/hyp.trn
sed -i 's/<blank> //g' ${dumpdir}/hyp.trn
filt.py -v ${model}/non_lang_syms.txt ${dumpdir}/hyp.trn > ${dumpdir}/hyp.trn.filtered
spm_decode --model=${model}/bpe.model --input_format=piece < ${dumpdir}/hyp.trn.filtered | sed -e "s/▁/ /g" > ${dumpdir}/hyp.wrd.trn

perl -p -e 's/^(.*)\(.+(.{15})\)$/$2 $1/g' ${dumpdir}/hyp.wrd.trn | sort > "${file}.txt"
rm -rf ${workdir}
