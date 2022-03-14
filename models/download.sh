#!/bin/bash

wget http://kaldi-asr.org/models/6/0006_callhome_diarization_v2_1a.tar.gz
tar xf 0006_callhome_diarization_v2_1a.tar.gz
mv  0006_callhome_diarization_v2_1a/exp/xvector_nnet_1a .

wget http://kaldi-asr.org/models/4/0004_tdnn_stats_asr_sad_1a.tar.gz
tar xf 0004_tdnn_stats_asr_sad_1a.tar.gz
mv exp/segmentation_1a/tdnn_stats_asr_sad_1a .

rm -rf 0004_tdnn_stats_asr_sad_1a.tar.gz \
	0006_callhome_diarization_v2_1a.tar.gz \
	0006_callhome_diarization_v2_1a \
	exp \
	conf \
	README_SAD.txt
